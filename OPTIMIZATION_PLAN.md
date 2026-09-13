# Alya VPN Performance Optimization Plan

**Version**: 0.0.15+  
**Date**: 2026-09-13  
**Target**: Alya VPN 0.0.14 → 1.0.0

---

## Executive Summary

Current Alya VPN 0.0.14 suffers from critical performance bottlenecks that limit throughput to ~10-50 Mbps with high latency. This plan addresses all 6 identified issues through binary protocol redesign, buffer pooling, multi-threading, and zero-copy I/O.

**Expected Gains**:
- **Throughput**: 10-50 Mbps → 500 Mbps - 1 Gbps+ (10-20x)
- **Latency**: 1-5 ms added → <0.1 ms added
- **CPU/Byte**: ~500 cycles → ~50 cycles (10x improvement)
- **Scalability**: 50 channels → 10,000+ channels

---

## 1. New Binary Frame Format Specification

### 1.1 Current AV01 Format (Text + Hex)
```
AV01 + type(2 hex) + nonce(24 hex) + tag(32 hex) + cipher_hex(2*N) + \n
```
- **Overhead**: 62 bytes fixed + 2x data size (hex encoding)
- **Example**: 100 byte payload → 262 bytes on wire (2.62x expansion)

### 1.2 New AV02 Binary Format
```
┌─────────────────────────────────────────────────────────────────┐
│ Magic (2)  │ Ver (1) │ Flags (1) │ Type (2) │ Channel ID (4)  │
│ 0x41 0x56  │ 0x02    │ 0x00      │ BE u16   │ BE u32          │
├─────────────────────────────────────────────────────────────────┤
│ Nonce (12 bytes)                                              │
├─────────────────────────────────────────────────────────────────┤
│ Ciphertext (variable) + Tag (16 bytes appended)               │
└─────────────────────────────────────────────────────────────────┘
```
- **Total Fixed Overhead**: 21 bytes (vs 62)
- **Data Encoding**: Raw binary (vs 2x hex)
- **Example**: 100 byte payload → 133 bytes on wire (1.33x)
- **Bandwidth Savings**: **49% reduction** vs AV01

### 1.3 Frame Flags (1 byte)
```
Bit 0: COMPRESSED    (1 = payload compressed with LZ4 before encryption)
Bit 1: FRAGMENTED    (1 = this is a fragment, more follows)
Bit 2: LAST_FRAGMENT (1 = last fragment in sequence)
Bit 3: PRIORITY      (1 = high priority / control frame)
Bit 4-7: RESERVED
```

### 1.4 Frame Types (u16)
| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| HANDSHAKE_REQ | 0x0001 | C→S | Initial key exchange |
| HANDSHAKE_RESP | 0x0002 | S→C | Key confirmation |
| CONNECT_REQ | 0x0003 | C→S | Open new channel |
| CONNECT_RESP | 0x0004 | S→C | Channel open result |
| DATA | 0x0005 | Both | Application data |
| CLOSE | 0x0006 | Both | Channel close |
| PING | 0x0007 | Both | Keep-alive |
| PONG | 0x0008 | Both | Keep-alive response |
| REKEY | 0x0009 | Both | Key rotation request |
| ERROR | 0x00FF | Both | Error notification |

### 1.5 Payload Structures (Binary, length-prefixed)

**CONNECT_REQ**: `channel_id(u32) | proto(u8) | host_len(u16) | host | port(u16)`
**CONNECT_RESP**: `channel_id(u32) | status(u16) | msg_len(u16) | msg`
**DATA**: `channel_id(u32) | data_len(u32) | data...`
**CLOSE**: `channel_id(u32) | reason(u16)`
**ERROR**: `error_code(u16) | msg_len(u16) | msg`

---

## 2. Buffer Pool Design

### 2.1 Design Goals
- Zero heap allocations in hot path
- Cache-friendly memory layout
- Lock-free for single-threaded use, lock-striped for multi-threaded
- Configurable pool sizes per buffer class

### 2.2 Buffer Classes

| Class | Size | Count | Use Case |
|-------|------|-------|----------|
| TINY | 256 B | 1024 | SOCKS5 handshake, small control frames |
| SMALL | 1 KiB | 512 | Typical control frames, DNS responses |
| MEDIUM | 4 KiB | 256 | Standard data frames (MTU-aligned) |
| LARGE | 16 KiB | 64 | Large data frames, file transfers |
| HUGE | 64 KiB | 16 | Jumbo frames, high-throughput bursts |

### 2.3 Pool Structure (C)
```c
typedef struct {
    uint8_t *memory;      // Contiguous backing store
    size_t block_size;    // Size of each buffer
    size_t block_count;   // Total blocks
    uint32_t *free_list;  // Stack of free indices (lock-free)
    uint32_t free_head;   // Atomic head index
    uint32_t free_tail;   // Atomic tail index
    _Atomic uint32_t allocated; // Stats
    _Atomic uint32_t peak_used; // Stats
} alya_buffer_pool_t;
```

### 2.4 API
```c
// Initialize pool (called once at startup)
int alya_buffer_pool_init(alya_buffer_pool_t *pool, size_t block_size, size_t block_count);

// Get buffer (returns NULL if exhausted - caller handles backpressure)
uint8_t *alya_buffer_acquire(alya_buffer_pool_t *pool);

// Return buffer to pool
void alya_buffer_release(alya_buffer_pool_t *pool, uint8_t *buf);

// Get stats
void alya_buffer_pool_stats(alya_buffer_pool_t *pool, alya_pool_stats_t *out);

// Pre-warm pool (allocate all blocks upfront)
void alya_buffer_pool_warm(alya_buffer_pool_t *pool);
```

### 2.5 Integration Points
- `alya_vpn_sock_recv_binary()` - reads directly into pool buffer
- `alya_vpn_sock_send_binary()` - takes ownership of pool buffer
- Frame packing/unpacking uses pool buffers
- Channel tables reference pool buffers directly (zero-copy)

---

## 3. Thread Architecture

### 3.1 Current: Single-Threaded Event Loop
```
┌─────────────────────────────────────────────────────────┐
│                    MAIN THREAD                          │
├─────────────────────────────────────────────────────────┤
│ accept → SOCKS5 → routing → encrypt → poll/sleep → loop│
│                    ↑                                    │
│            ALL CHANNELS BLOCK HERE                      │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Target: Pipeline Architecture

#### 3.2.1 Client-Side (Local Proxy)
```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│  ACCEPTOR   │────▶│  ROUTER      │────▶│  CRYPTO      │────▶│  TX WORKER  │
│  THREAD     │     │  THREAD      │     │  WORKERS     │     │  THREAD     │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
      │                   │                    │                   │
      ▼                   ▼                    ▼                   ▼
 - net::tcp_listen   - SOCKS5 handshake   - ChaCha20-Poly1305  - epoll/IOCP
 - net::tcp_accept   - Process resolve    - Encrypt/Decrypt    - Write to VPN
 - Non-blocking      - Channel assign     - Buffer pool mgmt   - Write to apps
 - 1 thread          - Split-tunnel       - N workers (CPU)    - 1 thread
```

**Thread Count**: 1 Acceptor + 1 Router + N Crypto (num_cores) + 1 TX = **N+3 threads**

#### 3.2.2 Server-Side (Forwarder)
```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│  ACCEPTOR   │────▶│  DEMUX       │────▶│  CRYPTO      │────▶│  FORWARDER  │
│  THREAD     │     │  THREAD      │     │  WORKERS     │     │  POOL       │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
      │                   │                    │                   │
      ▼                   ▼                    ▼                   ▼
 - net::tcp_listen   - Frame parsing      - Decrypt/Verify    - Per-channel
 - net::tcp_accept   - Channel routing    - Encrypt/Sign      - Worker threads
 - 1 thread          - Load balancing     - N workers (CPU)   - M threads
                                                                        (configurable)
```

**Thread Count**: 1 Acceptor + 1 Demux + N Crypto + M Forwarders = **N+M+2 threads**

### 3.3 Synchronization Primitives

| Mechanism | Use Case |
|-----------|----------|
| **MPSC Ring Buffer** | Inter-thread frame passing (lock-free) |
| **Channel Sharding** | Channel ID % N → Crypto Worker N (no locks) |
| **IOCP (Win) / epoll (Linux) / kqueue (macOS)** | Async I/O completion |
| **Condition Variables** | Thread parking/waking for backpressure |

### 3.4 Data Flow (Client Example)

```
Application → Acceptor accepts SOCKS5
              ↓
         Router: SOCKS5 handshake, process resolve, routing decision
              ↓
         If VPN: Channel assigned, frame queued to Crypto Worker[channel_id % N]
              ↓
         Crypto Worker: Encrypt → places encrypted frame in TX Ring Buffer
              ↓
         TX Worker: epoll_wait → writes to VPN socket
              ↓
         RX Worker (separate): epoll_wait → reads from VPN socket
              ↓
         Crypto Worker: Decrypt → places plaintext in App Ring Buffer
              ↓
         TX Worker: Writes to application socket
```

---

## 4. FFI Changes Needed

### 4.1 New FFI Declarations (ffi.alya additions)

```alya
# Buffer Pool Management
function alya_buffer_pool_init(pool_id: i32, block_size: i32, block_count: i32) -> i32
function alya_buffer_acquire(pool_id: i32) -> ptr
function alya_buffer_release(pool_id: i32, buf: ptr) -> void
function alya_buffer_pool_stats(pool_id: i32, out_allocated: ptr, out_peak: ptr) -> void

# Binary Frame API
function alya_vpn_pack_frame_bin(key_hex: str, msg_type: i32, channel_id: i32, payload: ptr, payload_len: i32, out_frame: ptr, out_frame_len: ptr) -> i32
function alya_vpn_unpack_frame_bin(key_hex: str, frame: ptr, frame_len: i32, out_msg_type: ptr, out_channel_id: ptr, out_payload: ptr, out_payload_len: ptr) -> i32

# Zero-Copy Socket I/O
function alya_vpn_sock_recv_bin(sock: i32, buf: ptr, max_len: i32) -> i32  # Returns bytes read, -1 on EOF
function alya_vpn_sock_send_bin(sock: i32, buf: ptr, len: i32) -> i32      # Returns bytes sent

# Async I/O (Platform-specific)
function alya_vpn_io_init() -> i32                          # Initialize IOCP/epoll/kqueue
function alya_vpn_io_register(sock: i32, events: i32, user_data: ptr) -> i32
function alya_vpn_io_unregister(sock: i32) -> i32
function alya_vpn_io_poll(events_out: ptr, max_events: i32, timeout_ms: i32) -> i32

# Channel Map (O(1) hash table)
function alya_vpn_chmap_init(max_channels: i32) -> i32
function alya_vpn_chmap_set(channel_id: i32, sock: i32, metadata: ptr) -> i32
function alya_vpn_chmap_get(channel_id: i32, out_sock: ptr, out_metadata: ptr) -> i32
function alya_vpn_chmap_remove(channel_id: i32) -> i32
function alya_vpn_chmap_iter(callback: ptr, user_data: ptr) -> i32  # For periodic cleanup

# Thread Pool
function alya_vpn_threadpool_init(worker_count: i32) -> i32
function alya_vpn_threadpool_submit(task_fn: ptr, user_data: ptr) -> i32
function alya_vpn_threadpool_shutdown() -> void

# LZ4 Compression (optional)
function alya_vpn_lz4_compress(src: ptr, src_len: i32, dst: ptr, dst_capacity: i32) -> i32
function alya_vpn_lz4_decompress(src: ptr, src_len: i32, dst: ptr, dst_capacity: i32) -> i32
```

### 4.2 Removed FFI (Deprecated)
- `alya_vpn_sock_recv_hex` → replaced by `alya_vpn_sock_recv_bin`
- `alya_vpn_sock_send_hex` → replaced by `alya_vpn_sock_send_bin`
- `alya_vpn_pack_data_payload` → frame packing handles this internally
- `alya_vpn_ch_id_at`, `alya_vpn_ch_sock_at` → replaced by `alya_vpn_chmap_iter`

---

## 5. C Implementation Changes

### 5.1 New Source Files
```
App/vpn/c/
├── buffer_pool.c/h       # Buffer pool implementation
├── frame_bin.c/h         # Binary frame pack/unpack (AV02)
├── io_multiplex.c/h      # Cross-platform IOCP/epoll/kqueue wrapper
├── channel_map.c/h       # O(1) channel hash map
├── thread_pool.c/h       # Work-stealing thread pool
├── crypto_worker.c/h     # Crypto worker thread logic
└── alya_vpn.c/h          # Updated main API (exports new symbols)
```

### 5.2 Modified Source Files
```
proc_resolver.c/h         # Add binary I/O, channel map, buffer pool init
crypto.c/h                # Add binary encrypt/decrypt (raw bytes, no hex)
```

### 5.3 Key Implementation Details

#### 5.3.1 Channel Map (O(1) Lookup)
```c
// Robin Hood hash map for minimal probes
#define ALYA_CHMAP_LOAD_FACTOR 0.75

typedef struct {
    uint32_t channel_id;
    int sock;
    void *metadata;  // Opaque pointer for context (tls, compression ctx, etc)
    uint8_t state;   // 0=empty, 1=occupied, 2=deleted
} chmap_entry_t;

typedef struct {
    chmap_entry_t *entries;
    size_t capacity;
    size_t size;
    size_t mask;     // capacity - 1 (power of 2)
} alya_chmap_t;
```

**Operations**: All O(1) average
- `set()`: ~3 probes average
- `get()`: ~2 probes average
- `remove()`: Tombstone + Robin Hood displacement
- `iter()`: Linear scan for cleanup (rare)

#### 5.3.2 Binary Frame Pack/Unpack
```c
// Pack: Returns total frame length written to out_frame
int alya_vpn_pack_frame_bin(
    const uint8_t *key,      // 32 bytes binary
    uint16_t msg_type,
    uint32_t channel_id,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_frame,      // Must have capacity: 21 + payload_len + 16
    uint32_t *out_frame_len
);

// Unpack: Returns 0 on success, -1 on auth fail, -2 on format error
// Output payload points into frame buffer (zero-copy) or allocated buffer
int alya_vpn_unpack_frame_bin(
    const uint8_t *key,
    const uint8_t *frame,
    uint32_t frame_len,
    uint16_t *out_msg_type,
    uint32_t *out_channel_id,
    const uint8_t **out_payload,    // Points into frame or separate buffer
    uint32_t *out_payload_len
);
```

#### 5.3.3 IOCP/epoll/kqueue Abstraction
```c
typedef enum {
    ALYA_IO_READ  = 1 << 0,
    ALYA_IO_WRITE = 1 << 1,
    ALYA_IO_ERROR = 1 << 2,
} alya_io_events_t;

typedef struct {
    int sock;
    alya_io_events_t events;
    void *user_data;  // Channel context pointer
} alya_io_event_t;

// Platform-specific backend selected at compile time
#if defined(_WIN32)
    // IOCP implementation
#elif defined(__linux__)
    // epoll implementation
#elif defined(__APPLE__)
    // kqueue implementation
#endif

int alya_io_init(void);
int alya_io_register(int sock, alya_io_events_t events, void *user_data);
int alya_io_unregister(int sock);
int alya_io_poll(alya_io_event_t *events, int max_events, int timeout_ms);
```

#### 5.3.4 Crypto Worker Thread
```c
typedef struct {
    alya_buffer_pool_t *encrypt_pool;
    alya_buffer_pool_t *decrypt_pool;
    mpsc_ring_t *input_queue;   // Plaintext frames to encrypt
    mpsc_ring_t *output_queue;  // Ciphertext frames to send
    uint8_t session_key[32];
    _Atomic bool running;
} crypto_worker_ctx_t;

void *crypto_worker_main(void *arg) {
    crypto_worker_ctx_t *ctx = arg;
    while (ctx->running) {
        frame_task_t *task = mpsc_pop(ctx->input_queue);
        if (!task) {
            // Park thread briefly
            futex_wait(&ctx->input_queue->head, 0, 1000); // 1ms
            continue;
        }
        // Encrypt/decrypt directly into pool buffers
        if (task->op == ENCRYPT) {
            uint8_t *out = alya_buffer_acquire(ctx->encrypt_pool);
            // ... encrypt task->payload into out ...
            mpsc_push(ctx->output_queue, out, task->len);
        } else {
            // DECRYPT
        }
        alya_buffer_release(task->pool, task->buf);
    }
    return NULL;
}
```

---

## 6. Alya Code Changes

### 6.1 Protocol Module (protocol.alya)

**New API** (binary-first, backward-compatible during transition):
```alya
# Frame format version negotiation
function proto_version() return 2 end

# Binary frame operations (primary)
function pack_frame_bin(session_key, msg_type, channel_id, payload, payload_len, out_frame)
function unpack_frame_bin(session_key, frame, frame_len, out_msg_type, out_channel_id, out_payload)

# Legacy text-frame compatibility (deprecated, for migration)
function pack_frame_v1(...)  # Old AV01
function unpack_frame_v1(...)

# Binary payload helpers
function pack_connect_req_bin(ch_id, proto, host, port, out_buf)
function unpack_connect_req_bin(buf, len, out_ch_id, out_proto, out_host, out_port)
function pack_data_bin(ch_id, data, data_len, out_buf)
function unpack_data_bin(buf, len, out_ch_id, out_data, out_data_len)
```

### 6.2 Crypto Module (crypto.alya)

```alya
# Binary key/encrypt/decrypt (no hex)
function vpn_derive_key_bin(passphrase, out_key_32bytes) -> void
function vpn_encrypt_bin(key_32, nonce_12, plaintext, plain_len, out_cipher, out_tag) -> i32
function vpn_decrypt_bin(key_32, nonce_12, ciphertext, cipher_len, tag_16, out_plain) -> i32

# Legacy hex API (deprecated)
function vpn_derive_key(...)  # Returns hex string
function vpn_encrypt(...)     # Hex in/out
function vpn_decrypt(...)     # Hex in/out
```

### 6.3 Local Proxy (local_proxy.alya) - Major Rewrite

**Key Changes**:
1. Replace `vpn_buffer += chunk` with ring buffer / pool buffer
2. Replace hex I/O with binary I/O
3. Replace O(N) channel iteration with channel map iteration
4. Replace 1ms sleep with IOCP/epoll wait
5. Add thread pool for crypto offload

**New Architecture**:
```alya
function vpn_run_client_proxy_v2(...)
    # 1. Initialize buffer pools
    alya_buffer_pool_init(POOL_RECV, 4096, 256)
    alya_buffer_pool_init(POOL_SEND, 4096, 256)
    
    # 2. Initialize channel map (O(1))
    alya_vpn_chmap_init(10000)
    
    # 3. Initialize IOCP/epoll
    alya_vpn_io_init()
    
    # 4. Start crypto worker threads
    alya_vpn_threadpool_init(num_cpus)
    
    # 5. Register listening socket
    alya_vpn_io_register(proxy_sock, READ, null)
    alya_vpn_io_register(vpn_sock, READ, null)
    
    # 6. Event loop
    while running
        events = alya_vpn_io_poll(event_array, 64, -1)  # Block indefinitely
        for event in events
            handle_event(event)
        end
    end
end
```

### 6.4 Server Forwarder (forwarder.alya) - Major Rewrite

Similar architecture to client but with:
- Multiple client connections (one per thread or worker pool)
- Forwarder pool for destination connections
- Connection pooling for frequently accessed destinations

### 6.5 FFI Module (ffi.alya)

Add all new declarations from Section 4.1, mark old ones `@deprecated`.

### 6.6 Router Module (router.alya)

No functional changes needed - but update to use binary API internally.

### 6.7 Main Entry Point (main.alya)

Add command-line flag for protocol version:
```
alya vpn client --proto-version 2 ...
alya vpn server --proto-version 2 ...
```

---

## 7. Migration Strategy

### Phase 1: Foundation (Week 1-2)
- [ ] Implement buffer pool C library
- [ ] Implement binary frame format (AV02) in C
- [ ] Implement channel hash map (O(1))
- [ ] Add FFI declarations for new APIs
- [ ] Unit tests for all new C components

### Phase 2: Async I/O (Week 2-3)
- [ ] Implement IOCP (Windows) backend
- [ ] Implement epoll (Linux) backend
- [ ] Implement kqueue (macOS) backend
- [ ] Add FFI for async I/O
- [ ] Integration tests with mock sockets

### Phase 3: Thread Pool & Crypto Workers (Week 3-4)
- [ ] Implement work-stealing thread pool
- [ ] Implement crypto worker threads
- [ ] Benchmark crypto throughput vs single-threaded
- [ ] Add backpressure handling

### Phase 4: Client Rewrite (Week 4-5)
- [ ] Rewrite local_proxy.alya with new architecture
- [ ] Support both AV01 (legacy) and AV02 (new) frames
- [ ] Auto-negotiate protocol version on connect
- [ ] Integration test with server

### Phase 5: Server Rewrite (Week 5-6)
- [ ] Rewrite forwarder.alya with new architecture
- [ ] Support multiple client connections efficiently
- [ ] Add connection pooling for destinations
- [ ] Load testing

### Phase 6: Optimization & Polish (Week 6-7)
- [ ] Profile and optimize hot paths
- [ ] Add LZ4 compression for compressible payloads
- [ ] Implement key rotation (REKEY frame)
- [ ] Documentation and benchmarks

---

## 8. Backward Compatibility

### 8.1 Protocol Negotiation
1. Client connects, sends `HANDSHAKE_REQ` with supported versions `[2, 1]`
2. Server responds with `HANDSHAKE_RESP` with selected version
3. Both sides switch to selected version for remainder of session

### 8.2 Fallback
- If server doesn't support AV02, falls back to AV01 transparently
- Old clients connecting to new server: server detects AV01 and responds in AV01
- No breaking changes to Alya API surface

---

## 9. Performance Targets

| Metric | Current (0.0.14) | Target (1.0.0) | Measurement |
|--------|------------------|----------------|-------------|
| Throughput (single stream) | ~50 Mbps | > 500 Mbps | iperf3 over localhost |
| Throughput (multi-stream) | ~100 Mbps | > 1 Gbps | 10 parallel iperf3 |
| Latency (added) | 1-5 ms | < 0.1 ms | Ping through tunnel |
| CPU per GB | ~50% core | < 10% core | `perf stat` / ETW |
| Max concurrent channels | ~50 | > 10,000 | Synthetic load test |
| Memory (1000 channels) | ~200 MB | < 50 MB | RSS measurement |
| Startup latency | ~200 ms | < 50 ms | Time to first byte |

---

## 10. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| IOCP/epoll/kqueue bugs | Medium | High | Extensive platform testing, CI on all 3 OS |
| Thread synchronization bugs | Medium | High | Use proven lock-free queues, stress test |
| Protocol negotiation failure | Low | Medium | Exhaustive version matrix testing |
| Buffer pool exhaustion | Low | Medium | Backpressure + dynamic pool growth |
| Crypto worker starvation | Low | Medium | Work-stealing queue, priority for control frames |
| Alya FFI instability | Low | High | Pin FFI signatures, integration test suite |

---

## 11. Appendix: Wire Format Examples

### AV02 CONNECT_REQ (client → server)
```
Offset  Length  Field
0       2       Magic: 0x41 0x56 ('A' 'V')
2       1       Version: 0x02
3       1       Flags: 0x00
4       2       Type: 0x0003 (CONNECT_REQ)
6       4       Channel ID: 0x00000001 (BE)
10      12      Nonce: [12 random bytes]
22      2       Proto: 0x0001 (TCP)
24      2       Host length: 0x000D (13)
26      13      Host: "example.com"
39      2       Port: 0x1F90 (8080)
41      N       Ciphertext (encrypted payload)
41+N    16      Poly1305 Tag
```

### AV02 DATA (bidirectional)
```
Offset  Length  Field
0       2       Magic: 0x41 0x56
2       1       Version: 0x02
3       1       Flags: 0x00 (or 0x01 if compressed)
4       2       Type: 0x0005 (DATA)
6       4       Channel ID
10      12      Nonce
22      4       Data length (BE u32)
26      N       Ciphertext
26+N    16      Poly1305 Tag
```

---

*End of Optimization Plan*