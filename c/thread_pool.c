#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#include "thread_pool.h"
#include "buffer_pool.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

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
#define THREAD_RETURN_TYPE unsigned __stdcall
#define THREAD_RETURN_VAL 0
#else
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
typedef pthread_mutex_t AlyaMutex;
#define MUTEX_INIT(m) pthread_mutex_init(m, NULL)
#define MUTEX_LOCK(m) pthread_mutex_lock(m)
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define THREAD_RETURN_TYPE void *
#define THREAD_RETURN_VAL NULL
#endif

// ============================================================================
// Cross-Platform Atomic Operations
// GCC/Clang built-ins operate on standard pointers without requiring _Atomic type,
// avoiding Apple Clang type mismatch errors on volatile / standard integer types.
// ============================================================================
#if defined(__GNUC__) || defined(__clang__)
#define alya_atomic_load(ptr, order)           __atomic_load_n((ptr), (order))
#define alya_atomic_store(ptr, val, order)      __atomic_store_n((ptr), (val), (order))
#define alya_atomic_fetch_add(ptr, val, order)  __atomic_fetch_add((ptr), (val), (order))
#define alya_atomic_fetch_sub(ptr, val, order)  __atomic_fetch_sub((ptr), (val), (order))
#define alya_atomic_init(ptr, val)             __atomic_store_n((ptr), (val), __ATOMIC_RELAXED)
#define ALYA_ORDER_RELAXED                     __ATOMIC_RELAXED
#define ALYA_ORDER_ACQUIRE                     __ATOMIC_ACQUIRE
#define ALYA_ORDER_RELEASE                     __ATOMIC_RELEASE
#elif defined(_MSC_VER)
#include <intrin.h>
#define ALYA_ORDER_RELAXED                     0
#define ALYA_ORDER_ACQUIRE                     0
#define ALYA_ORDER_RELEASE                     0
#define alya_atomic_load(ptr, order)           (*(ptr))
#define alya_atomic_store(ptr, val, order)      (*(ptr) = (val))
#define alya_atomic_init(ptr, val)             (*(ptr) = (val))
static inline int alya_atomic_fetch_add_int(volatile int *ptr, int val) {
    return (int)_InterlockedExchangeAdd((volatile long *)ptr, (long)val);
}
static inline int alya_atomic_fetch_sub_int(volatile int *ptr, int val) {
    return (int)_InterlockedExchangeAdd((volatile long *)ptr, -(long)val);
}
static inline uint64_t alya_atomic_fetch_add_u64(volatile uint64_t *ptr, uint64_t val) {
    return (uint64_t)_InterlockedExchangeAdd64((volatile long long *)ptr, (long long)val);
}
#define alya_atomic_fetch_add(ptr, val, order) \
    (sizeof(*(ptr)) == 8 ? alya_atomic_fetch_add_u64((volatile uint64_t *)(ptr), (uint64_t)(val)) \
                         : alya_atomic_fetch_add_int((volatile int *)(ptr), (int)(val)))
#define alya_atomic_fetch_sub(ptr, val, order) \
    (sizeof(*(ptr)) == 8 ? alya_atomic_fetch_add_u64((volatile uint64_t *)(ptr), -(long long)(val)) \
                         : alya_atomic_fetch_sub_int((volatile int *)(ptr), (int)(val)))
#else
#define ALYA_ORDER_RELAXED                     0
#define ALYA_ORDER_ACQUIRE                     0
#define ALYA_ORDER_RELEASE                     0
#define alya_atomic_load(ptr, order)           (*(ptr))
#define alya_atomic_store(ptr, val, order)      (*(ptr) = (val))
#define alya_atomic_init(ptr, val)             (*(ptr) = (val))
#define alya_atomic_fetch_add(ptr, val, order) ((*(ptr)) += (val))
#define alya_atomic_fetch_sub(ptr, val, order) ((*(ptr)) -= (val))
#endif

// ============================================================================
// Simple JSON Parser for Work Submission
// ============================================================================

static int json_get_int(const char *json, const char *key, int *out) {
    const char *p = strstr(json, key);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    *out = atoi(p);
    return 0;
}

static int json_get_str(const char *json, const char *key, char *out, int max_len) {
    const char *p = strstr(json, key);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '"') p++;
    const char *end = p;
    while (*end && *end != '"' && *end != ',' && *end != '}' && (end - p) < max_len - 1) end++;
    int len = end - p;
    if (len >= max_len) len = max_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

// ============================================================================
// Platform Abstraction
// ============================================================================

static void alya_event_init(AlyaEventHandle *evt) {
#if defined(_WIN32)
    *evt = CreateEventA(NULL, TRUE, FALSE, NULL);
#else
    pthread_cond_init(evt, NULL);
#endif
}

static void alya_event_signal(AlyaEventHandle *evt) {
#if defined(_WIN32)
    SetEvent(*evt);
#else
    pthread_cond_broadcast(evt);
#endif
}

static void __attribute__((unused)) alya_event_wait(AlyaEventHandle *evt, AlyaMutex *mutex, int timeout_ms) {
#if defined(_WIN32)
    MUTEX_UNLOCK(mutex);
    WaitForSingleObject(*evt, timeout_ms > 0 ? (DWORD)timeout_ms : INFINITE);
    MUTEX_LOCK(mutex);
#else
    if (timeout_ms > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(evt, mutex, &ts);
    } else {
        pthread_cond_wait(evt, mutex);
    }
#endif
}

static void alya_event_destroy(AlyaEventHandle *evt) {
#if defined(_WIN32)
    CloseHandle(*evt);
#else
    pthread_cond_destroy(evt);
#endif
}

static AlyaThreadHandle alya_thread_create(THREAD_RETURN_TYPE (*func)(void *), void *arg) {
#if defined(_WIN32)
    return (AlyaThreadHandle)_beginthreadex(NULL, 0, func, arg, 0, NULL);
#else
    pthread_t tid = 0;
    if (pthread_create(&tid, NULL, func, arg) != 0) {
        return 0;
    }
    return tid;
#endif
}

static void alya_thread_join(AlyaThreadHandle handle) {
#if defined(_WIN32)
    if (handle) {
        WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
    }
#else
    if (handle != 0) {
        pthread_join(handle, NULL);
    }
#endif
}


static int alya_get_cpu_count(void) {
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    return (int)sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

// ============================================================================
// Lock-Free MPSC Queue Implementation
// ============================================================================

void alya_work_queue_init(AlyaWorkQueue *queue, int capacity) {
    queue->items = (AlyaWorkItem *)calloc(capacity, sizeof(AlyaWorkItem));
    queue->capacity = capacity;
    alya_atomic_init(&queue->head, 0);
    alya_atomic_init(&queue->tail, 0);
    alya_atomic_init(&queue->count, 0);
}

int alya_work_queue_push(AlyaWorkQueue *queue, AlyaWorkItem *item) {
    int head = alya_atomic_load(&queue->head, ALYA_ORDER_RELAXED);
    int next_head = (head + 1) % queue->capacity;
    int count = alya_atomic_load(&queue->count, ALYA_ORDER_ACQUIRE);

    if (count >= queue->capacity - 1) {
        return -1; // Queue full
    }

    // Copy item to queue
    queue->items[head] = *item;

    // Publish: update head and count
    alya_atomic_store(&queue->head, next_head, ALYA_ORDER_RELEASE);
    alya_atomic_fetch_add(&queue->count, 1, ALYA_ORDER_RELEASE);

    return 0;
}

int alya_work_queue_pop(AlyaWorkQueue *queue, AlyaWorkItem *item) {
    int tail = alya_atomic_load(&queue->tail, ALYA_ORDER_RELAXED);
    int count = alya_atomic_load(&queue->count, ALYA_ORDER_ACQUIRE);

    if (count == 0) {
        return -1; // Queue empty
    }

    // Copy item from queue
    *item = queue->items[tail];

    // Update tail and count
    int next_tail = (tail + 1) % queue->capacity;
    alya_atomic_store(&queue->tail, next_tail, ALYA_ORDER_RELEASE);
    alya_atomic_fetch_sub(&queue->count, 1, ALYA_ORDER_RELEASE);

    return 0;
}

int alya_work_queue_size(AlyaWorkQueue *queue) {
    return alya_atomic_load(&queue->count, ALYA_ORDER_ACQUIRE);
}

// ============================================================================
// Global Thread Pool Instance
// ============================================================================

static AlyaThreadPool s_pool = {0};
static int s_pool_initialized = 0;

// ============================================================================
// Crypto Worker Thread
// ============================================================================

static THREAD_RETURN_TYPE alya_crypto_worker(void *arg) {
    AlyaWorkerThread *worker = (AlyaWorkerThread *)arg;
    AlyaThreadPool *pool = worker->pool;
    AlyaWorkQueue *queue = &pool->crypto_queue;
    AlyaWorkItem item;

    while (!pool->shutting_down) {
        if (alya_work_queue_pop(queue, &item) == 0) {
            // Process crypto work
            AlyaCryptoWork *cw = &item.data.crypto;

            if (cw->work_type == ALYA_WORK_CRYPTO_ENCRYPT) {
                // Encrypt: plaintext -> frame
                uint8_t key[32];
                if (cw->key_hex) {
                    // Use provided key
                    for (int i = 0; i < 32; ++i) {
                        int hi = cw->key_hex[i * 2];
                        int lo = cw->key_hex[i * 2 + 1];
                        int v_hi = (hi >= '0' && hi <= '9') ? hi - '0' :
                                   (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                                   (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
                        int v_lo = (lo >= '0' && lo <= '9') ? lo - '0' :
                                   (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                                   (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
                        key[i] = (uint8_t)((v_hi << 4) | v_lo);
                    }
                } else if (alya_vpn_has_session_key()) {
                    const uint8_t *session_key = alya_vpn_get_session_key_bin();
                    memcpy(key, session_key, 32);
                } else {
                    cw->result_code = -2;
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                // Get buffer data
                uint8_t *plaintext = alya_vpn_buffer_data(cw->buffer_id);
                if (!plaintext || cw->payload_len <= 0) {
                    cw->result_code = -2;
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                // Generate nonce
                uint8_t nonce[12];
                alya_vpn_get_random_bytes(nonce, 12);

                // Encrypt
                uint8_t *ciphertext = plaintext; // In-place encryption
                alya_vpn_chacha20_xor(key, nonce, 1, plaintext, ciphertext, (size_t)cw->payload_len);

                // Generate tag
                uint8_t poly_key[32] = {0};
                alya_vpn_chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);
                uint8_t tag[16];
                alya_vpn_poly1305_mac(ciphertext, (size_t)cw->payload_len, poly_key, tag);

                // Build frame in buffer
                uint8_t *frame = plaintext; // Overwrite plaintext with frame
                frame[0] = 'A';
                frame[1] = 'V';
                frame[2] = 0x01;
                frame[3] = (uint8_t)cw->msg_type;
                memcpy(&frame[4], nonce, 12);
                memcpy(&frame[16], tag, 16);
                // ciphertext already at offset 32

                cw->out_frame_len = 32 + cw->payload_len;
                alya_vpn_buffer_set_used(cw->buffer_id, cw->out_frame_len);
                cw->result_code = 0;

            } else if (cw->work_type == ALYA_WORK_CRYPTO_DECRYPT) {
                // Decrypt: frame -> plaintext
                uint8_t key[32];
                if (cw->key_hex) {
                    for (int i = 0; i < 32; ++i) {
                        int hi = cw->key_hex[i * 2];
                        int lo = cw->key_hex[i * 2 + 1];
                        int v_hi = (hi >= '0' && hi <= '9') ? hi - '0' :
                                   (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                                   (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
                        int v_lo = (lo >= '0' && lo <= '9') ? lo - '0' :
                                   (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                                   (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
                        key[i] = (uint8_t)((v_hi << 4) | v_lo);
                    }
                } else if (alya_vpn_has_session_key()) {
                    const uint8_t *session_key = alya_vpn_get_session_key_bin();
                    memcpy(key, session_key, 32);
                } else {
                    cw->result_code = -2;
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                uint8_t *frame = alya_vpn_buffer_data(cw->buffer_id);
                if (!frame || cw->frame_len < 32) {
                    cw->result_code = -2;
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                // Verify magic
                if (frame[0] != 'A' || frame[1] != 'V' || frame[2] != 0x01) {
                    cw->result_code = -2;
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                uint8_t msg_type = frame[3];
                uint8_t *nonce = &frame[4];
                uint8_t *expected_tag = &frame[16];
                uint8_t *ciphertext = &frame[32];
                int raw_len = cw->frame_len - 32;

                if (raw_len < 0 || raw_len > (int)(ALYA_BUFFER_SIZE - 32)) {
                    cw->result_code = -2;
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                // Verify tag
                uint8_t poly_key[32] = {0};
                alya_vpn_chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);
                uint8_t computed_tag[16];
                alya_vpn_poly1305_mac(ciphertext, (size_t)raw_len, poly_key, computed_tag);

                int diff = 0;
                for (int i = 0; i < 16; ++i) {
                    diff |= (computed_tag[i] ^ expected_tag[i]);
                }
                if (diff != 0) {
                    cw->result_code = -1; // Auth failed
                    alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
                    continue;
                }

                // Decrypt in-place
                alya_vpn_chacha20_xor(key, nonce, 1, ciphertext, ciphertext, (size_t)raw_len);
                alya_vpn_buffer_set_used(cw->buffer_id, (size_t)raw_len);

                // Store msg_type for caller
                item.type = (int)msg_type;
                cw->result_code = 0;
            }

            alya_atomic_fetch_add(&pool->crypto_completed, 1, ALYA_ORDER_RELAXED);
        } else {
            // Queue empty, sleep briefly to avoid burning CPU cycles
#if defined(_WIN32)
            Sleep(2);
#else
            usleep(2000);
#endif
        }
    }

    return THREAD_RETURN_VAL;
}

// ============================================================================
// I/O Worker Thread
// ============================================================================

static THREAD_RETURN_TYPE alya_io_worker(void *arg) {
    AlyaWorkerThread *worker = (AlyaWorkerThread *)arg;
    AlyaThreadPool *pool = worker->pool;
    AlyaWorkQueue *queue = &pool->io_queue;
    AlyaWorkItem item;

    while (!pool->shutting_down) {
        if (alya_work_queue_pop(queue, &item) == 0) {
            AlyaIOWork *iw = &item.data.io;

            if (iw->work_type == ALYA_WORK_IO_READ) {
                int n = alya_vpn_sock_recv_into_buffer(iw->sock, iw->buffer_id, (int)iw->len);
                iw->result_bytes = n;
            } else if (iw->work_type == ALYA_WORK_IO_WRITE) {
                int n = alya_vpn_sock_send_from_buffer(iw->sock, iw->buffer_id, iw->offset, iw->len);
                iw->result_bytes = n;
            } else if (iw->work_type == ALYA_WORK_IO_ACCEPT) {
#if defined(_WIN32)
                iw->accept_sock = (int)accept((SOCKET)iw->sock, NULL, NULL);
#else
                iw->accept_sock = accept(iw->sock, NULL, NULL);
#endif
                iw->result_bytes = (iw->accept_sock >= 0) ? 1 : -1;
            }

            alya_atomic_fetch_add(&pool->io_completed, 1, ALYA_ORDER_RELAXED);
        } else {
            // Queue empty, sleep briefly to avoid burning CPU cycles
#if defined(_WIN32)
            Sleep(2);
#else
            usleep(2000);
#endif
        }
    }

    return THREAD_RETURN_VAL;
}

// ============================================================================
// Thread Pool API Implementation
// ============================================================================

int alya_vpn_thread_pool_init(int crypto_workers, int io_workers) {
    if (s_pool_initialized) {
        return 0;
    }

    int cpu_count = alya_get_cpu_count();
    if (cpu_count <= 0) cpu_count = 4;

    // Auto-configure worker counts
    if (crypto_workers <= 0) {
        crypto_workers = cpu_count > 4 ? 4 : cpu_count;
    }
    if (crypto_workers > ALYA_MAX_CRYPTO_WORKERS) {
        crypto_workers = ALYA_MAX_CRYPTO_WORKERS;
    }

    if (io_workers <= 0) {
        io_workers = cpu_count * 2;
        if (io_workers > ALYA_MAX_IO_WORKERS) io_workers = ALYA_MAX_IO_WORKERS;
    }
    if (io_workers > ALYA_MAX_IO_WORKERS) {
        io_workers = ALYA_MAX_IO_WORKERS;
    }

    // Initialize work queues
    alya_work_queue_init(&s_pool.crypto_queue, ALYA_WORK_QUEUE_SIZE);
    alya_work_queue_init(&s_pool.io_queue, ALYA_WORK_QUEUE_SIZE);

    // Initialize channel-worker map
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        s_pool.channel_worker_map[i] = -1;
    }

    // Initialize shutdown event
    alya_event_init(&s_pool.shutdown_event);

    alya_atomic_init(&s_pool.crypto_submitted, 0);
    alya_atomic_init(&s_pool.crypto_completed, 0);
    alya_atomic_init(&s_pool.io_submitted, 0);
    alya_atomic_init(&s_pool.io_completed, 0);
    alya_atomic_init(&s_pool.queue_full_drops, 0);
    alya_atomic_init(&s_pool.shutting_down, 0);

    // Initialize buffer pool first (required for crypto/I/O workers)
    alya_vpn_buffer_pool_init();

    // Start crypto workers
    s_pool.crypto_worker_count = crypto_workers;
    for (int i = 0; i < crypto_workers; ++i) {
        s_pool.crypto_workers[i].id = i;
        s_pool.crypto_workers[i].type = 0;
        s_pool.crypto_workers[i].running = 1;
        s_pool.crypto_workers[i].queue = NULL; // Crypto workers share global queue
        s_pool.crypto_workers[i].pool = &s_pool;
        s_pool.crypto_workers[i].thread_handle = alya_thread_create(alya_crypto_worker, &s_pool.crypto_workers[i]);
#if defined(_WIN32)
        if (!s_pool.crypto_workers[i].thread_handle) {
#else
        if (s_pool.crypto_workers[i].thread_handle == 0) {
#endif
            fprintf(stderr, "[ThreadPool] Failed to create crypto worker %d\n", i);
            s_pool.crypto_worker_count = i;
            break;
        }
    }

    // Start I/O workers
    s_pool.io_worker_count = io_workers;
    for (int i = 0; i < io_workers; ++i) {
        s_pool.io_workers[i].id = i;
        s_pool.io_workers[i].type = 1;
        s_pool.io_workers[i].running = 1;
        s_pool.io_workers[i].queue = &s_pool.io_queue;
        s_pool.io_workers[i].pool = &s_pool;
        s_pool.io_workers[i].thread_handle = alya_thread_create(alya_io_worker, &s_pool.io_workers[i]);
#if defined(_WIN32)
        if (!s_pool.io_workers[i].thread_handle) {
#else
        if (s_pool.io_workers[i].thread_handle == 0) {
#endif
            fprintf(stderr, "[ThreadPool] Failed to create I/O worker %d\n", i);
            s_pool.io_worker_count = i;
            break;
        }
    }

    s_pool_initialized = 1;
    fprintf(stderr, "[ThreadPool] Initialized: %d crypto workers, %d I/O workers\n",
            s_pool.crypto_worker_count, s_pool.io_worker_count);

    return 0;
}

void alya_vpn_thread_pool_shutdown(void) {
    if (!s_pool_initialized) return;

    // Signal shutdown
    alya_atomic_store(&s_pool.shutting_down, 1, ALYA_ORDER_RELEASE);
    alya_event_signal(&s_pool.shutdown_event);

    // Wait for crypto workers
    for (int i = 0; i < s_pool.crypto_worker_count; ++i) {
#if defined(_WIN32)
        if (s_pool.crypto_workers[i].thread_handle) {
#else
        if (s_pool.crypto_workers[i].thread_handle != 0) {
#endif
            alya_thread_join(s_pool.crypto_workers[i].thread_handle);
            s_pool.crypto_workers[i].thread_handle = 0;
        }
    }

    // Wait for I/O workers
    for (int i = 0; i < s_pool.io_worker_count; ++i) {
#if defined(_WIN32)
        if (s_pool.io_workers[i].thread_handle) {
#else
        if (s_pool.io_workers[i].thread_handle != 0) {
#endif
            alya_thread_join(s_pool.io_workers[i].thread_handle);
            s_pool.io_workers[i].thread_handle = 0;
        }
    }

    // Cleanup
    alya_event_destroy(&s_pool.shutdown_event);


    // Free queue memory
    free(s_pool.crypto_queue.items);
    s_pool.crypto_queue.items = NULL;
    free(s_pool.io_queue.items);
    s_pool.io_queue.items = NULL;

    // Shutdown buffer pool
    alya_vpn_buffer_pool_shutdown();

    s_pool_initialized = 0;
    fprintf(stderr, "[ThreadPool] Shutdown complete\n");
}

int alya_vpn_submit_crypto_work(AlyaCryptoWork *work) {
    if (!s_pool_initialized) return -2;

    AlyaWorkItem item = {0};
    item.type = work->work_type;
    item.data.crypto = *work;
    item.worker_id = -1; // No affinity for crypto
    item.sequence = 0;

    if (alya_work_queue_push(&s_pool.crypto_queue, &item) != 0) {
        alya_atomic_fetch_add(&s_pool.queue_full_drops, 1, ALYA_ORDER_RELAXED);
        return -1;
    }

    alya_atomic_fetch_add(&s_pool.crypto_submitted, 1, ALYA_ORDER_RELAXED);
    return 0;
}

int alya_vpn_submit_io_work(AlyaIOWork *work) {
    if (!s_pool_initialized) return -2;

    AlyaWorkItem item = {0};
    item.type = work->work_type;
    item.data.io = *work;
    item.worker_id = -1;
    item.sequence = 0;

    if (alya_work_queue_push(&s_pool.io_queue, &item) != 0) {
        alya_atomic_fetch_add(&s_pool.queue_full_drops, 1, ALYA_ORDER_RELAXED);
        return -1;
    }

    alya_atomic_fetch_add(&s_pool.io_submitted, 1, ALYA_ORDER_RELAXED);
    return 0;
}

void alya_vpn_assign_channel_worker(int channel_id, int worker_id) {
    if (!s_pool_initialized) return;
    if (channel_id < 0 || channel_id >= ALYA_MAX_CHANNELS) return;
    if (worker_id < -1 || worker_id >= s_pool.io_worker_count) return;

    s_pool.channel_worker_map[channel_id] = worker_id;
}

int alya_vpn_get_channel_worker(int channel_id) {
    if (!s_pool_initialized) return -1;
    if (channel_id < 0 || channel_id >= ALYA_MAX_CHANNELS) return -1;
    return s_pool.channel_worker_map[channel_id];
}

void alya_vpn_thread_pool_stats(uint64_t *crypto_submitted, uint64_t *crypto_completed,
                                 uint64_t *io_submitted, uint64_t *io_completed,
                                 uint64_t *queue_full_drops,
                                 int *crypto_workers, int *io_workers) {
    if (crypto_submitted) *crypto_submitted = alya_atomic_load(&s_pool.crypto_submitted, ALYA_ORDER_RELAXED);
    if (crypto_completed) *crypto_completed = alya_atomic_load(&s_pool.crypto_completed, ALYA_ORDER_RELAXED);
    if (io_submitted) *io_submitted = alya_atomic_load(&s_pool.io_submitted, ALYA_ORDER_RELAXED);
    if (io_completed) *io_completed = alya_atomic_load(&s_pool.io_completed, ALYA_ORDER_RELAXED);
    if (queue_full_drops) *queue_full_drops = alya_atomic_load(&s_pool.queue_full_drops, ALYA_ORDER_RELAXED);
    if (crypto_workers) *crypto_workers = s_pool.crypto_worker_count;
    if (io_workers) *io_workers = s_pool.io_worker_count;
}

int alya_vpn_thread_pool_is_initialized(void) {
    return s_pool_initialized;
}

void alya_vpn_thread_pool_drain(void) {
    if (!s_pool_initialized) return;

    // Wait for queues to empty
    while (alya_work_queue_size(&s_pool.crypto_queue) > 0 ||
           alya_work_queue_size(&s_pool.io_queue) > 0) {
#if defined(_WIN32)
        Sleep(1);
#else
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 1000000L; // 1ms
        nanosleep(&ts, NULL);
#endif
    }

}

// ============================================================================
// FFI Wrapper Functions (called from Alya via FFI)
// ============================================================================

int alya_vpn_ffi_thread_pool_init(int crypto_workers, int io_workers) {
    return alya_vpn_thread_pool_init(crypto_workers, io_workers);
}

void alya_vpn_ffi_thread_pool_shutdown(void) {
    alya_vpn_thread_pool_shutdown();
}

int alya_vpn_ffi_submit_crypto_work(const char *work_json) {
    if (!s_pool_initialized) return -2;

    AlyaCryptoWork work = {0};
    json_get_int(work_json, "work_type", &work.work_type);
    json_get_int(work_json, "buffer_id", &work.buffer_id);
    json_get_int(work_json, "msg_type", &work.msg_type);
    json_get_int(work_json, "payload_len", &work.payload_len);
    json_get_int(work_json, "frame_len", &work.frame_len);
    json_get_int(work_json, "channel_id", &work.channel_id);

    char key_hex[65];
    if (json_get_str(work_json, "key_hex", key_hex, sizeof(key_hex)) == 0 && strlen(key_hex) > 0) {
        work.key_hex = key_hex;
    }

    AlyaWorkItem item = {0};
    item.type = work.work_type;
    item.data.crypto = work;
    item.worker_id = -1;
    item.sequence = 0;

    if (alya_work_queue_push(&s_pool.crypto_queue, &item) != 0) {
        alya_atomic_fetch_add(&s_pool.queue_full_drops, 1, ALYA_ORDER_RELAXED);
        return -1;
    }

    alya_atomic_fetch_add(&s_pool.crypto_submitted, 1, ALYA_ORDER_RELAXED);
    return 0;
}

int alya_vpn_ffi_submit_io_work(const char *work_json) {
    if (!s_pool_initialized) return -2;

    AlyaIOWork work = {0};
    json_get_int(work_json, "work_type", &work.work_type);
    json_get_int(work_json, "sock", &work.sock);
    json_get_int(work_json, "buffer_id", &work.buffer_id);
    json_get_int(work_json, "offset", (int *)&work.offset);
    json_get_int(work_json, "len", (int *)&work.len);
    json_get_int(work_json, "channel_id", &work.channel_id);

    AlyaWorkItem item = {0};
    item.type = work.work_type;
    item.data.io = work;
    item.worker_id = -1;
    item.sequence = 0;

    if (alya_work_queue_push(&s_pool.io_queue, &item) != 0) {
        alya_atomic_fetch_add(&s_pool.queue_full_drops, 1, ALYA_ORDER_RELAXED);
        return -1;
    }

    alya_atomic_fetch_add(&s_pool.io_submitted, 1, ALYA_ORDER_RELAXED);
    return 0;
}

void alya_vpn_ffi_assign_channel_worker(int channel_id, int worker_id) {
    alya_vpn_assign_channel_worker(channel_id, worker_id);
}

int alya_vpn_ffi_get_channel_worker(int channel_id) {
    return alya_vpn_get_channel_worker(channel_id);
}

int alya_vpn_ffi_thread_pool_is_initialized(void) {
    return alya_vpn_thread_pool_is_initialized();
}

void alya_vpn_ffi_thread_pool_drain(void) {
    alya_vpn_thread_pool_drain();
}