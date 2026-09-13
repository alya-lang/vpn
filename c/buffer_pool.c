#include "buffer_pool.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
typedef CRITICAL_SECTION AlyaMutex;
#define MUTEX_INIT(m) InitializeCriticalSection(m)
#define MUTEX_LOCK(m) EnterCriticalSection(m)
#define MUTEX_UNLOCK(m) LeaveCriticalSection(m)
#define MUTEX_DESTROY(m) DeleteCriticalSection(m)
#define GET_THREAD_ID() GetCurrentThreadId()
#else
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
typedef pthread_mutex_t AlyaMutex;
#define MUTEX_INIT(m) pthread_mutex_init(m, NULL)
#define MUTEX_LOCK(m) pthread_mutex_lock(m)
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define GET_THREAD_ID() (int)pthread_self()
#endif

// ============================================================================
// Thread-Local Storage for Unpack
// ============================================================================

#if defined(_MSC_VER)
#define ALYA_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define ALYA_THREAD_LOCAL _Thread_local
#else
#define ALYA_THREAD_LOCAL __thread
#endif

static ALYA_THREAD_LOCAL char s_unpack_plain_buf[65536];
static ALYA_THREAD_LOCAL int s_last_unpack_type_buffer = 0;

// ============================================================================
// Global Buffer Pool Instance
// ============================================================================

static AlyaBufferPool s_pool = {0};
static int s_pool_initialized = 0;

// ============================================================================
// Mutex Helpers
// ============================================================================

static void mutex_init(AlyaMutex *m) {
    MUTEX_INIT(m);
}

static void mutex_lock(AlyaMutex *m) {
    MUTEX_LOCK(m);
}

static void mutex_unlock(AlyaMutex *m) {
    MUTEX_UNLOCK(m);
}

static void mutex_destroy(AlyaMutex *m) {
    MUTEX_DESTROY(m);
}

// ============================================================================
// Buffer Pool Initialization
// ============================================================================

void alya_vpn_buffer_pool_init(void) {
    if (s_pool_initialized) return;

    // Allocate single contiguous memory block for all buffers (cache-friendly)
    size_t total_size = (size_t)ALYA_BUFFER_COUNT * ALYA_BUFFER_SIZE;
    uint8_t *pool_memory = NULL;
#if defined(_WIN32)
    // Windows: Use VirtualAlloc for aligned allocation
    pool_memory = (uint8_t *)VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pool_memory) {
        pool_memory = (uint8_t *)malloc(total_size);
    }
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    // C11: Use aligned_alloc
    pool_memory = (uint8_t *)aligned_alloc(64, total_size);
    if (!pool_memory) {
        pool_memory = (uint8_t *)malloc(total_size);
    }
#else
    // Fallback: Use malloc (may not be cache-line aligned)
    pool_memory = (uint8_t *)malloc(total_size);
#endif
    if (!pool_memory) {
        fprintf(stderr, "[BufferPool] FATAL: Failed to allocate %zu MB buffer pool\n", total_size / (1024 * 1024));
        return;
    }

    // Initialize mutex
    AlyaMutex *mutex = (AlyaMutex *)malloc(sizeof(AlyaMutex));
    if (!mutex) {
        free(pool_memory);
        return;
    }
    mutex_init(mutex);
    s_pool.mutex = mutex;

    // Initialize buffers
    for (int i = 0; i < ALYA_BUFFER_COUNT; ++i) {
        s_pool.buffers[i].data = pool_memory + (size_t)i * ALYA_BUFFER_SIZE;
        s_pool.buffers[i].used = 0;
        s_pool.buffers[i].capacity = ALYA_BUFFER_SIZE;
        s_pool.buffers[i].ref_count = 0;
        s_pool.buffers[i].in_use = 0;
        s_pool.buffers[i].owner_thread = -1;

        // Build free list (LIFO for cache locality)
        s_pool.free_list[i] = ALYA_BUFFER_COUNT - 1 - i;
    }

    s_pool.free_head = 0;
    s_pool.free_count = ALYA_BUFFER_COUNT;
    s_pool.thread_cache_count = 0;

    // Zero statistics
    s_pool.total_acquires = 0;
    s_pool.total_releases = 0;
    s_pool.cache_hits = 0;
    s_pool.cache_misses = 0;
    s_pool.contention_events = 0;

    s_pool_initialized = 1;
    fprintf(stderr, "[BufferPool] Initialized: %d buffers × %d KB = %zu MB\n",
            ALYA_BUFFER_COUNT, ALYA_BUFFER_SIZE / 1024, total_size / (1024 * 1024));
}

void alya_vpn_buffer_pool_shutdown(void) {
    if (!s_pool_initialized) return;

    if (s_pool.mutex) {
        mutex_destroy((AlyaMutex *)s_pool.mutex);
        free(s_pool.mutex);
        s_pool.mutex = NULL;
    }

    // Free contiguous pool memory (first buffer's data points to start)
    if (s_pool.buffers[0].data) {
#if defined(_WIN32)
        VirtualFree(s_pool.buffers[0].data, 0, MEM_RELEASE);
#else
        free(s_pool.buffers[0].data);
#endif
        s_pool.buffers[0].data = NULL;
    }

    s_pool_initialized = 0;
    fprintf(stderr, "[BufferPool] Shutdown complete\n");
}

// ============================================================================
// Buffer Acquire/Release
// ============================================================================

int alya_vpn_buffer_acquire(void) {
    if (!s_pool_initialized) return -1;

    int thread_id = GET_THREAD_ID();
    int buffer_id = -1;

    // Try thread-local cache first (no lock needed)
    if (s_pool.thread_cache_count > 0) {
        buffer_id = s_pool.thread_cache[--s_pool.thread_cache_count];
        s_pool.cache_hits++;
    } else {
        s_pool.cache_misses++;
        // Fall back to global pool with lock
        mutex_lock((AlyaMutex *)s_pool.mutex);
        if (s_pool.free_count > 0) {
            buffer_id = s_pool.free_list[--s_pool.free_count];
        }
        mutex_unlock((AlyaMutex *)s_pool.mutex);
    }

    if (buffer_id >= 0) {
        s_pool.buffers[buffer_id].in_use = 1;
        s_pool.buffers[buffer_id].ref_count = 1;
        s_pool.buffers[buffer_id].used = 0;
        s_pool.buffers[buffer_id].owner_thread = thread_id;
        s_pool.total_acquires++;
    } else {
        // Pool exhausted - could grow or return error
        s_pool.contention_events++;
    }

    return buffer_id;
}

void alya_vpn_buffer_release(int buffer_id) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return;

    AlyaBuffer *buf = &s_pool.buffers[buffer_id];

    // Decrement ref count
    if (buf->ref_count > 0) {
        buf->ref_count--;
    }

    // Only return to pool when ref count reaches 0
    if (buf->ref_count == 0) {
        buf->in_use = 0;
        buf->used = 0;
        buf->owner_thread = -1;
        s_pool.total_releases++;

        int thread_id = GET_THREAD_ID();

        // Try to put in thread-local cache first
        if (s_pool.thread_cache_count < 4) {
            s_pool.thread_cache[s_pool.thread_cache_count++] = buffer_id;
        } else {
            // Cache full, return to global pool
            mutex_lock((AlyaMutex *)s_pool.mutex);
            if (s_pool.free_count < ALYA_BUFFER_COUNT) {
                s_pool.free_list[s_pool.free_count++] = buffer_id;
            }
            mutex_unlock((AlyaMutex *)s_pool.mutex);
        }
    }
}

// Reference counting for shared buffer usage (e.g., scatter/gather)
void alya_vpn_buffer_ref(int buffer_id) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return;
    s_pool.buffers[buffer_id].ref_count++;
}

// ============================================================================
// Buffer Accessors
// ============================================================================

uint8_t *alya_vpn_buffer_data(int buffer_id) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return NULL;
    if (!s_pool.buffers[buffer_id].in_use) return NULL;
    return s_pool.buffers[buffer_id].data;
}

size_t alya_vpn_buffer_used(int buffer_id) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return 0;
    return s_pool.buffers[buffer_id].used;
}

void alya_vpn_buffer_set_used(int buffer_id, size_t used) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return;
    if (used > ALYA_BUFFER_SIZE) used = ALYA_BUFFER_SIZE;
    s_pool.buffers[buffer_id].used = used;
}

void alya_vpn_buffer_reset(int buffer_id) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return;
    s_pool.buffers[buffer_id].used = 0;
}

size_t alya_vpn_buffer_capacity(int buffer_id) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return 0;
    return ALYA_BUFFER_SIZE;
}

// ============================================================================
// Zero-Copy Socket I/O
// ============================================================================

int alya_vpn_sock_recv_into_buffer(int sock, int buffer_id, int max_bytes) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return -1;

    AlyaBuffer *buf = &s_pool.buffers[buffer_id];
    if (!buf->in_use) return -1;

    int to_read = max_bytes;
    if (to_read <= 0 || to_read > (int)(buf->capacity - buf->used)) {
        to_read = (int)(buf->capacity - buf->used);
    }
    if (to_read <= 0) return 0;

    int n = recv((SOCKET)sock, (char *)(buf->data + buf->used), to_read, 0);
    if (n > 0) {
        buf->used += (size_t)n;
    }
    return n;
}

int alya_vpn_sock_send_from_buffer(int sock, int buffer_id, size_t offset, size_t len) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return -1;

    AlyaBuffer *buf = &s_pool.buffers[buffer_id];
    if (!buf->in_use) return -1;
    if (offset >= buf->used) return 0;
    if (offset + len > buf->used) len = buf->used - offset;

    int n = send((SOCKET)sock, (const char *)(buf->data + offset), (int)len, 0);
    return n;
}

// ============================================================================
// Scatter/Gather I/O (writev / WSASend)
// ============================================================================

int alya_vpn_sock_send_frame(int sock, const void *header, size_t header_len,
                              int payload_buffer_id, size_t payload_offset, size_t payload_len) {
    if (!header || header_len != ALYA_FRAME_HEADER_SIZE) return -1;
    if (payload_len == 0) {
        // Just send header
        return send((SOCKET)sock, (const char *)header, (int)header_len, 0);
    }

    if (!s_pool_initialized || payload_buffer_id < 0 || payload_buffer_id >= ALYA_BUFFER_COUNT) return -1;

    AlyaBuffer *payload_buf = &s_pool.buffers[payload_buffer_id];
    if (!payload_buf->in_use) return -1;
    if (payload_offset >= payload_buf->used) return -1;
    if (payload_offset + payload_len > payload_buf->used) return -1;

#if defined(_WIN32)
    // Windows: WSASend with WSABUF array
    WSABUF bufs[2];
    bufs[0].buf = (CHAR *)header;
    bufs[0].len = (ULONG)header_len;
    bufs[1].buf = (CHAR *)(payload_buf->data + payload_offset);
    bufs[1].len = (ULONG)payload_len;

    DWORD sent = 0;
    DWORD flags = 0;
    int result = WSASend((SOCKET)sock, bufs, 2, &sent, flags, NULL, NULL);
    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return 0;
        return -1;
    }
    return (int)sent;
#else
    // POSIX: writev
    struct iovec iov[2];
    iov[0].iov_base = (void *)header;
    iov[0].iov_len = header_len;
    iov[1].iov_base = payload_buf->data + payload_offset;
    iov[1].iov_len = payload_len;

    ssize_t n = writev(sock, iov, 2);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return (int)n;
#endif
}

int alya_vpn_sock_recv_frame(int sock, int buffer_id, int max_payload) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return -1;

    AlyaBuffer *buf = &s_pool.buffers[buffer_id];
    if (!buf->in_use) return -1;

    // Read header first (32 bytes)
    uint8_t *header = buf->data;
    int header_received = 0;
    while (header_received < (int)ALYA_FRAME_HEADER_SIZE) {
        int n = recv((SOCKET)sock, (char *)(header + header_received),
                     ALYA_FRAME_HEADER_SIZE - header_received, 0);
        if (n <= 0) return n; // EOF or error
        header_received += n;
    }

    // Parse payload length from frame
    // Frame: [2B magic][1B version][1B type][12B nonce][16B tag][N ciphertext]
    // Total frame len = 32 + payload_len
    // We know header is 32 bytes, payload follows
    int payload_len = max_payload;
    if (payload_len > (int)(buf->capacity - ALYA_FRAME_HEADER_SIZE)) {
        payload_len = (int)(buf->capacity - ALYA_FRAME_HEADER_SIZE);
    }

    // Read payload
    uint8_t *payload = buf->data + ALYA_FRAME_HEADER_SIZE;
    int payload_received = 0;
    while (payload_received < payload_len) {
        int n = recv((SOCKET)sock, (char *)(payload + payload_received),
                     payload_len - payload_received, 0);
        if (n <= 0) {
            if (payload_received == 0) return n;
            break; // Partial read
        }
        payload_received += n;
    }

    buf->used = ALYA_FRAME_HEADER_SIZE + (size_t)payload_received;
    return ALYA_FRAME_HEADER_SIZE + payload_received;
}

// ============================================================================
// Frame Construction Helpers
// ============================================================================

const uint8_t *alya_vpn_pack_frame_into_buffer(int buffer_id, const char *key_hex, int msg_type,
                                                const char *payload, int payload_len,
                                                int *out_frame_len) {
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return NULL;
    if (msg_type <= 0 || payload_len < 0 || payload_len > ALYA_MAX_PAYLOAD || !out_frame_len) return NULL;

    AlyaBuffer *buf = &s_pool.buffers[buffer_id];
    if (!buf->in_use) return NULL;

    uint8_t key[32];
    static char s_session_key_hex[65] = {0};
    static uint8_t s_session_key_bin[32] = {0};
    static int s_has_session_key = 0;

    // Get key (same logic as crypto.c)
    extern int alya_vpn_has_session_key(void);
    extern const uint8_t *alya_vpn_get_session_key_bin(void);

    if (s_has_session_key) {
        memcpy(key, s_session_key_bin, 32);
    } else if (!key_hex || strlen(key_hex) < 64) {
        return NULL;
    } else {
        // Parse hex key
        for (int i = 0; i < 32; ++i) {
            int hi = key_hex[i * 2];
            int lo = key_hex[i * 2 + 1];
            int v_hi = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
            int v_lo = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
            key[i] = (uint8_t)((v_hi << 4) | v_lo);
        }
    }

    // Generate random 12-byte nonce directly
    uint8_t nonce[12];
    extern void alya_vpn_get_random_bytes(uint8_t *buf, size_t len);
    alya_vpn_get_random_bytes(nonce, 12);

    // 1. One-time Poly1305 key generation via ChaCha20 block 0
    uint8_t poly_key[32] = {0};
    extern void alya_vpn_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);
    alya_vpn_chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);

    // 2. Encrypt plaintext starting at counter 1
    uint8_t *ciphertext = buf->data + ALYA_FRAME_HEADER_SIZE;
    if (payload_len > 0 && payload) {
        alya_vpn_chacha20_xor(key, nonce, 1, (const uint8_t *)payload, ciphertext, (size_t)payload_len);
    }

    // 3. Compute Poly1305 MAC tag
    uint8_t tag[16];
    extern void alya_vpn_poly1305_mac(const uint8_t *msg, size_t msg_len,
                                       const uint8_t key[32], uint8_t tag[16]);
    alya_vpn_poly1305_mac(ciphertext, (size_t)payload_len, poly_key, tag);

    // 4. Build binary frame in buffer
    uint8_t *frame = buf->data;
    frame[0] = 'A';
    frame[1] = 'V';
    frame[2] = 0x01;  // version
    frame[3] = (uint8_t)msg_type;
    memcpy(&frame[4], nonce, 12);
    memcpy(&frame[16], tag, 16);
    // Ciphertext already in place at offset 32

    *out_frame_len = ALYA_FRAME_HEADER_SIZE + payload_len;
    buf->used = (size_t)*out_frame_len;

    return frame;
}

const char *alya_vpn_unpack_frame_from_buffer(const char *key_hex, int buffer_id, int frame_len) {
    s_last_unpack_type_buffer = 0;
    if (!s_pool_initialized || buffer_id < 0 || buffer_id >= ALYA_BUFFER_COUNT) return NULL;
    if (frame_len < ALYA_FRAME_HEADER_SIZE) return NULL;

    AlyaBuffer *buf = &s_pool.buffers[buffer_id];
    if (!buf->in_use) return NULL;

    const uint8_t *frame = buf->data;

    // Verify magic and version
    if (frame[0] != 'A' || frame[1] != 'V' || frame[2] != 0x01) {
        return NULL;
    }

    uint8_t key[32];
    static char s_session_key_hex[65] = {0};
    static uint8_t s_session_key_bin[32] = {0};
    static int s_has_session_key = 0;

    if (s_has_session_key) {
        memcpy(key, s_session_key_bin, 32);
    } else if (!key_hex || strlen(key_hex) < 64) {
        return NULL;
    } else {
        for (int i = 0; i < 32; ++i) {
            int hi = key_hex[i * 2];
            int lo = key_hex[i * 2 + 1];
            int v_hi = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
            int v_lo = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
            key[i] = (uint8_t)((v_hi << 4) | v_lo);
        }
    }

    // Message type
    uint8_t msg_type = frame[3];

    // Nonce (12 bytes at offset 4)
    const uint8_t *nonce = &frame[4];

    // Tag (16 bytes at offset 16)
    const uint8_t *expected_tag = &frame[16];

    // Ciphertext (after 32-byte header)
    int raw_len = frame_len - ALYA_FRAME_HEADER_SIZE;
    if (raw_len < 0 || raw_len > (int)sizeof(s_unpack_plain_buf) - 8) return NULL;

    const uint8_t *ciphertext = &frame[ALYA_FRAME_HEADER_SIZE];

    // 1. One-time Poly1305 key generation via ChaCha20 block 0
    uint8_t poly_key[32] = {0};
    extern void alya_vpn_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);
    alya_vpn_chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);

    // 2. Compute and verify Poly1305 MAC
    uint8_t computed_tag[16];
    extern void alya_vpn_poly1305_mac(const uint8_t *msg, size_t msg_len,
                                       const uint8_t key[32], uint8_t tag[16]);
    alya_vpn_poly1305_mac(ciphertext, (size_t)raw_len, poly_key, computed_tag);

    int diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (computed_tag[i] ^ expected_tag[i]);
    }
    if (diff != 0) {
        return NULL; // MAC verification failed!
    }

    // 3. Decrypt ciphertext starting at counter 1
    if (raw_len > 0) {
        alya_vpn_chacha20_xor(key, nonce, 1, ciphertext, (uint8_t *)s_unpack_plain_buf, (size_t)raw_len);
    }
    s_unpack_plain_buf[raw_len] = '\0';
    s_last_unpack_type_buffer = (int)msg_type;

    return s_unpack_plain_buf;
}

int alya_vpn_unpack_frame_buffer_type(void) {
    return s_last_unpack_type_buffer;
}

// ============================================================================
// Statistics
// ============================================================================

void alya_vpn_buffer_pool_stats(void) {
    if (!s_pool_initialized) {
        printf("[BufferPool] Not initialized\n");
        return;
    }

    mutex_lock((AlyaMutex *)s_pool.mutex);
    int free_count = s_pool.free_count;
    int in_use = ALYA_BUFFER_COUNT - free_count;
    mutex_unlock((AlyaMutex *)s_pool.mutex);

    printf("\n=== Buffer Pool Statistics ===\n");
    printf("Total Buffers:     %d\n", ALYA_BUFFER_COUNT);
    printf("Buffer Size:       %d KB\n", ALYA_BUFFER_SIZE / 1024);
    printf("Free:              %d\n", free_count);
    printf("In Use:            %d\n", in_use);
    printf("Total Acquires:    %llu\n", (unsigned long long)s_pool.total_acquires);
    printf("Total Releases:    %llu\n", (unsigned long long)s_pool.total_releases);
    printf("Cache Hits:        %llu\n", (unsigned long long)s_pool.cache_hits);
    printf("Cache Misses:      %llu\n", (unsigned long long)s_pool.cache_misses);
    printf("Contention Events: %llu\n", (unsigned long long)s_pool.contention_events);
    if (s_pool.total_acquires > 0) {
        double hit_rate = (double)s_pool.cache_hits / (s_pool.cache_hits + s_pool.cache_misses) * 100.0;
        printf("Cache Hit Rate:    %.1f%%\n", hit_rate);
    }
    printf("================================\n\n");
}

void alya_vpn_buffer_pool_get_stats(uint64_t *acquires, uint64_t *releases,
                                     uint64_t *cache_hits, uint64_t *cache_misses,
                                     uint64_t *contention) {
    if (acquires) *acquires = s_pool.total_acquires;
    if (releases) *releases = s_pool.total_releases;
    if (cache_hits) *cache_hits = s_pool.cache_hits;
    if (cache_misses) *cache_misses = s_pool.cache_misses;
    if (contention) *contention = s_pool.contention_events;
}

// ============================================================================
// Expose internal crypto functions for buffer pool use
// ============================================================================

// These are implemented in crypto.c but needed by buffer_pool.c
// We declare them here to avoid circular dependency

// In crypto.c, add these declarations:
/*
// Expose for buffer_pool.c
void alya_vpn_get_random_bytes(uint8_t *buf, size_t len);
void alya_vpn_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);
void alya_vpn_poly1305_mac(const uint8_t *msg, size_t msg_len,
                            const uint8_t key[32], uint8_t tag[16]);
int alya_vpn_has_session_key(void);
const uint8_t *alya_vpn_get_session_key_bin(void);
*/