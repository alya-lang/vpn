#ifndef ALYA_VPN_THREAD_POOL_H
#define ALYA_VPN_THREAD_POOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Thread Pool Configuration
// ============================================================================

#define ALYA_MAX_CRYPTO_WORKERS 16
#define ALYA_MAX_IO_WORKERS 32
#define ALYA_WORK_QUEUE_SIZE 1024
#define ALYA_MAX_CHANNELS 8192

// Work item types
typedef enum {
    ALYA_WORK_CRYPTO_ENCRYPT = 1,
    ALYA_WORK_CRYPTO_DECRYPT = 2,
    ALYA_WORK_IO_READ = 3,
    ALYA_WORK_IO_WRITE = 4,
    ALYA_WORK_IO_ACCEPT = 5,
    ALYA_WORK_SHUTDOWN = 255
} AlyaWorkType;

// Forward declarations
typedef struct AlyaCryptoWork AlyaCryptoWork;
typedef struct AlyaIOWork AlyaIOWork;
typedef struct AlyaWorkItem AlyaWorkItem;
typedef struct AlyaWorkerThread AlyaWorkerThread;
typedef struct AlyaThreadPool AlyaThreadPool;

// ============================================================================
// Work Item Structures
// ============================================================================

// Crypto work: encrypt/decrypt frames
struct AlyaCryptoWork {
    int work_type;                    // ALYA_WORK_CRYPTO_ENCRYPT or ALYA_WORK_CRYPTO_DECRYPT
    int buffer_id;                    // Buffer pool buffer ID
    const char *key_hex;              // 64-char hex key (or NULL for session key)
    int msg_type;                     // Message type for encryption
    int payload_len;                  // Plaintext length for encryption
    int frame_len;                    // Frame length for decryption
    int result_code;                  // Output: 0 = success, -1 = auth fail, -2 = error
    int out_frame_len;                // Output: frame length for encryption
    int channel_id;                   // Associated channel ID for routing
};

// I/O work: socket read/write
struct AlyaIOWork {
    int work_type;                    // ALYA_WORK_IO_READ, WRITE, ACCEPT
    int sock;                         // Socket descriptor
    int buffer_id;                    // Buffer pool buffer ID
    size_t offset;                    // Offset in buffer
    size_t len;                       // Length to read/write
    int channel_id;                   // Channel ID for routing
    int result_bytes;                 // Output: bytes read/written
    int accept_sock;                  // Output: accepted socket for ACCEPT work
};

// Generic work item
struct AlyaWorkItem {
    int type;                         // ALYA_WORK_* type
    union {
        AlyaCryptoWork crypto;
        AlyaIOWork io;
    } data;
    int worker_id;                    // Assigned worker (for affinity)
    int sequence;                     // Sequence number for ordering
};

// ============================================================================
// Lock-Free MPSC Queue
// ============================================================================

typedef struct {
    AlyaWorkItem *items;
    int capacity;
    volatile int head;                // Producer index
    volatile int tail;                // Consumer index
    volatile int count;               // Current count
} AlyaWorkQueue;

// ============================================================================
// Worker Thread
// ============================================================================

struct AlyaWorkerThread {
    int id;                           // Worker ID
    int type;                         // 0 = crypto, 1 = I/O
    void *thread_handle;              // Platform thread handle
    int running;                      // Running flag
    AlyaWorkQueue *queue;             // Work queue (for I/O workers with affinity)
    AlyaThreadPool *pool;             // Back-reference to pool
};

// ============================================================================
// Thread Pool
// ============================================================================

struct AlyaThreadPool {
    // Crypto workers
    AlyaWorkerThread crypto_workers[ALYA_MAX_CRYPTO_WORKERS];
    int crypto_worker_count;
    AlyaWorkQueue crypto_queue;

    // I/O workers
    AlyaWorkerThread io_workers[ALYA_MAX_IO_WORKERS];
    int io_worker_count;
    AlyaWorkQueue io_queue;

    // Channel to I/O worker affinity mapping
    int channel_worker_map[ALYA_MAX_CHANNELS];

    // Synchronization
    void *shutdown_event;             // Event/semaphore for shutdown
    volatile int shutting_down;       // Shutdown flag

    // Statistics
    uint64_t crypto_submitted;
    uint64_t crypto_completed;
    uint64_t io_submitted;
    uint64_t io_completed;
    uint64_t queue_full_drops;
};

// ============================================================================
// Thread Pool API
// ============================================================================

// Initialize thread pool with specified worker counts
// crypto_workers: number of crypto worker threads (0 = auto, default 4)
// io_workers: number of I/O worker threads (0 = auto, default 8)
// Returns 0 on success, -1 on failure
int alya_vpn_thread_pool_init(int crypto_workers, int io_workers);

// Shutdown thread pool and wait for all workers to exit
void alya_vpn_thread_pool_shutdown(void);

// Submit crypto work (encrypt/decrypt)
// Returns 0 on success, -1 if queue full, -2 if not initialized
int alya_vpn_submit_crypto_work(AlyaCryptoWork *work);

// Submit I/O work (read/write/accept)
// Returns 0 on success, -1 if queue full, -2 if not initialized
int alya_vpn_submit_io_work(AlyaIOWork *work);

// Assign channel to specific I/O worker for affinity
// channel_id: channel identifier
// worker_id: I/O worker index (0 to io_worker_count-1), or -1 for round-robin
void alya_vpn_assign_channel_worker(int channel_id, int worker_id);

// Get assigned I/O worker for channel
int alya_vpn_get_channel_worker(int channel_id);

// Get thread pool statistics
void alya_vpn_thread_pool_stats(uint64_t *crypto_submitted, uint64_t *crypto_completed,
                                 uint64_t *io_submitted, uint64_t *io_completed,
                                 uint64_t *queue_full_drops,
                                 int *crypto_workers, int *io_workers);

// Check if thread pool is initialized
int alya_vpn_thread_pool_is_initialized(void);

// Wait for all pending work to complete (drain queues)
void alya_vpn_thread_pool_drain(void);

// ============================================================================
// Work Queue API (for direct use by workers)
// ============================================================================

// Initialize work queue
void alya_work_queue_init(AlyaWorkQueue *queue, int capacity);

// Push work item (MPSC - multiple producers, single consumer)
// Returns 0 on success, -1 if full
int alya_work_queue_push(AlyaWorkQueue *queue, AlyaWorkItem *item);

// Pop work item (single consumer)
// Returns 0 on success, -1 if empty
int alya_work_queue_pop(AlyaWorkQueue *queue, AlyaWorkItem *item);

// Get current queue size
int alya_work_queue_size(AlyaWorkQueue *queue);

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_THREAD_POOL_H