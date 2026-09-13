#ifndef ALYA_VPN_BUFFER_POOL_H
#define ALYA_VPN_BUFFER_POOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Buffer Pool Configuration
// ============================================================================
// 128 buffers × 64KB = 8MB total pool size
// Each buffer: 32-byte frame header + 65504 bytes payload (fits in 64KB)
#define ALYA_BUFFER_COUNT 128
#define ALYA_BUFFER_SIZE 65536  // 64KB
#define ALYA_FRAME_HEADER_SIZE 32
#define ALYA_MAX_PAYLOAD (ALYA_BUFFER_SIZE - ALYA_FRAME_HEADER_SIZE)

// ============================================================================
// Buffer Pool State
// ============================================================================

typedef struct {
    uint8_t *data;                    // Buffer data (64KB)
    size_t used;                      // Bytes currently in use
    size_t capacity;                  // Total capacity (64KB)
    uint32_t ref_count;               // Reference count for shared usage
    int in_use;                       // Boolean: buffer is checked out
    int owner_thread;                 // Thread ID of owner (for debugging)
} AlyaBuffer;

// Buffer pool with free list and per-thread cache
typedef struct {
    AlyaBuffer buffers[ALYA_BUFFER_COUNT];
    int free_list[ALYA_BUFFER_COUNT];
    int free_head;                    // Index of first free buffer
    int free_count;                   // Number of free buffers

    // Per-thread cache (reduces contention)
    // Each thread caches up to 4 buffers locally
    int thread_cache[4];
    int thread_cache_count;

    // Mutex for thread safety
    void *mutex;                      // Platform-specific mutex handle

    // Statistics
    uint64_t total_acquires;
    uint64_t total_releases;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t contention_events;
} AlyaBufferPool;

// ============================================================================
// Buffer Pool API
// ============================================================================

// Initialize the global buffer pool (call once at startup)
void alya_vpn_buffer_pool_init(void);

// Shutdown and free all resources
void alya_vpn_buffer_pool_shutdown(void);

// Acquire a buffer from the pool
// Returns buffer index (0 to ALYA_BUFFER_COUNT-1) or -1 on failure
int alya_vpn_buffer_acquire(void);

// Release a buffer back to the pool
// buffer_id: index returned by alya_vpn_buffer_acquire
void alya_vpn_buffer_release(int buffer_id);

// Get pointer to buffer data
// Returns NULL if buffer_id is invalid
uint8_t *alya_vpn_buffer_data(int buffer_id);

// Get used bytes in buffer
size_t alya_vpn_buffer_used(int buffer_id);

// Set used bytes in buffer (for manual frame construction)
void alya_vpn_buffer_set_used(int buffer_id, size_t used);

// Reset buffer (mark as empty, keep ownership)
void alya_vpn_buffer_reset(int buffer_id);

// Get buffer capacity (always ALYA_BUFFER_SIZE)
size_t alya_vpn_buffer_capacity(int buffer_id);

// ============================================================================
// Zero-Copy Socket I/O API
// ============================================================================

// Receive directly into pool buffer (eliminates copy)
// sock: socket descriptor
// buffer_id: buffer from alya_vpn_buffer_acquire()
// max_bytes: maximum bytes to receive (up to ALYA_MAX_PAYLOAD)
// Returns: bytes received (>0), 0 on EOF, -1 on error
int alya_vpn_sock_recv_into_buffer(int sock, int buffer_id, int max_bytes);

// Send from pool buffer (zero-copy)
// sock: socket descriptor
// buffer_id: buffer from alya_vpn_buffer_acquire()
// offset: offset within buffer to start sending from
// len: number of bytes to send
// Returns: bytes sent (>0), 0 on EOF, -1 on error
int alya_vpn_sock_send_from_buffer(int sock, int buffer_id, size_t offset, size_t len);

// Scatter/gather send: frame header + payload in single syscall
// Uses writev (POSIX) or WSASend (Windows) for zero-copy framing
// sock: socket descriptor
// header: pointer to 32-byte frame header (magic, version, type, nonce, tag)
// header_len: must be ALYA_FRAME_HEADER_SIZE (32)
// payload_buffer_id: buffer containing payload (after header)
// payload_offset: offset of payload in buffer
// payload_len: length of payload
// Returns: total bytes sent (header + payload) or -1 on error
int alya_vpn_sock_send_frame(int sock, const void *header, size_t header_len,
                              int payload_buffer_id, size_t payload_offset, size_t payload_len);

// Scatter/gather receive: read frame header then payload
// sock: socket descriptor
// buffer_id: buffer to receive into (header + payload)
// max_payload: maximum payload bytes to read
// Returns: total bytes received (header + payload) or -1 on error
// On success, buffer contains: [32-byte header][payload...]
int alya_vpn_sock_recv_frame(int sock, int buffer_id, int max_payload);

// ============================================================================
// Frame Construction Helpers (integrates with binary frame format)
// ============================================================================

// Build binary frame directly in pool buffer
// buffer_id: acquired buffer
// key_hex: 64-char hex key (or NULL to use session key)
// msg_type: message type (1 byte)
// payload: plaintext payload
// payload_len: payload length
// out_frame_len: output total frame length (header + ciphertext)
// Returns: pointer to frame in buffer (or NULL on error)
// Frame layout: [2B magic][1B version][1B type][12B nonce][16B tag][N ciphertext]
const uint8_t *alya_vpn_pack_frame_into_buffer(int buffer_id, const char *key_hex, int msg_type,
                                                const char *payload, int payload_len,
                                                int *out_frame_len);

// Parse binary frame from pool buffer
// buffer_id: buffer containing frame
// frame_len: total frame length
// Returns: pointer to decrypted plaintext in static thread-local buffer, or NULL on error
const char *alya_vpn_unpack_frame_from_buffer(const char *key_hex, int buffer_id, int frame_len);

// Get message type of last successfully unpacked frame
int alya_vpn_unpack_frame_buffer_type(void);

// ============================================================================
// Statistics and Debugging
// ============================================================================

// Print buffer pool statistics
void alya_vpn_buffer_pool_stats(void);

// Get pool statistics
void alya_vpn_buffer_pool_get_stats(uint64_t *acquires, uint64_t *releases,
                                     uint64_t *cache_hits, uint64_t *cache_misses,
                                     uint64_t *contention);

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_BUFFER_POOL_H