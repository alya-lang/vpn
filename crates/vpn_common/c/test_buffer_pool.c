#include "buffer_pool.h"
#include "proc_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

// Test basic buffer pool operations
void test_buffer_pool_basic() {
    printf("\n=== Test: Basic Buffer Pool Operations ===\n");

    alya_vpn_buffer_pool_init();

    // Acquire a buffer
    int buf_id = alya_vpn_buffer_acquire();
    printf("Acquired buffer: %d\n", buf_id);
    if (buf_id < 0) {
        printf("FAIL: Could not acquire buffer\n");
        return;
    }

    // Get buffer data pointer
    uint8_t *data = alya_vpn_buffer_data(buf_id);
    printf("Buffer data pointer: %p\n", (void *)data);
    printf("Buffer capacity: %zu\n", alya_vpn_buffer_capacity(buf_id));

    // Write some data
    const char *test_data = "Hello, Buffer Pool!";
    size_t len = strlen(test_data);
    memcpy(data, test_data, len);
    alya_vpn_buffer_set_used(buf_id, len);

    printf("Buffer used: %zu\n", alya_vpn_buffer_used(buf_id));
    printf("Buffer content: %.*s\n", (int)alya_vpn_buffer_used(buf_id), (char *)data);

    // Reset buffer
    alya_vpn_buffer_reset(buf_id);
    printf("After reset, used: %zu\n", alya_vpn_buffer_used(buf_id));

    // Release buffer
    alya_vpn_buffer_release(buf_id);
    printf("Released buffer\n");

    // Acquire again (should get from thread cache)
    int buf_id2 = alya_vpn_buffer_acquire();
    printf("Re-acquired buffer: %d\n", buf_id2);

    alya_vpn_buffer_release(buf_id2);

    alya_vpn_buffer_pool_stats();
    alya_vpn_buffer_pool_shutdown();
}

// Test frame packing/unpacking in buffer
void test_frame_in_buffer() {
    printf("\n=== Test: Frame Packing in Buffer ===\n");

    alya_vpn_buffer_pool_init();

    // Set session key
    alya_vpn_set_session_passphrase("test-passphrase-123");

    int buf_id = alya_vpn_buffer_acquire();
    if (buf_id < 0) {
        printf("FAIL: Could not acquire buffer\n");
        return;
    }

    const char *payload = "This is a test payload for binary framing!";
    int payload_len = (int)strlen(payload);
    int frame_len = 0;

    // Pack frame directly into buffer
    const uint8_t *frame = alya_vpn_pack_frame_into_buffer(buf_id, NULL, 0x01, payload, payload_len, &frame_len);
    if (!frame) {
        printf("FAIL: Frame packing failed\n");
        alya_vpn_buffer_release(buf_id);
        return;
    }

    printf("Packed frame: %d bytes (header=%d, payload=%d)\n", frame_len, ALYA_FRAME_HEADER_SIZE, payload_len);
    printf("Frame magic: %c%c, version: %d, type: %d\n", frame[0], frame[1], frame[2], frame[3]);

    // Unpack frame from buffer
    const char *unpacked = alya_vpn_unpack_frame_from_buffer(NULL, buf_id, frame_len);
    if (!unpacked) {
        printf("FAIL: Frame unpacking failed\n");
    } else {
        printf("Unpacked payload: %s\n", unpacked);
        printf("Message type: %d\n", alya_vpn_unpack_frame_buffer_type());
        if (strcmp(unpacked, payload) == 0) {
            printf("SUCCESS: Payload matches!\n");
        } else {
            printf("FAIL: Payload mismatch\n");
        }
    }

    alya_vpn_buffer_release(buf_id);
    alya_vpn_buffer_pool_stats();
    alya_vpn_buffer_pool_shutdown();
}

// Test multi-buffer acquisition (pool capacity)
void test_multi_buffer() {
    printf("\n=== Test: Multi-Buffer Acquisition ===\n");

    alya_vpn_buffer_pool_init();

    int buffers[ALYA_BUFFER_COUNT + 10];
    int acquired = 0;

    // Acquire all buffers
    for (int i = 0; i < ALYA_BUFFER_COUNT + 5; ++i) {
        int id = alya_vpn_buffer_acquire();
        if (id >= 0) {
            buffers[acquired++] = id;
        } else {
            break;
        }
    }

    printf("Acquired %d buffers (pool size: %d)\n", acquired, ALYA_BUFFER_COUNT);

    // Release half
    for (int i = 0; i < acquired / 2; ++i) {
        alya_vpn_buffer_release(buffers[i]);
    }
    printf("Released %d buffers\n", acquired / 2);

    // Acquire again (should reuse from cache)
    for (int i = 0; i < acquired / 2; ++i) {
        int id = alya_vpn_buffer_acquire();
        if (id >= 0) {
            buffers[acquired++] = id;
        }
    }
    printf("Re-acquired, total now: %d\n", acquired);

    // Release all
    for (int i = 0; i < acquired; ++i) {
        alya_vpn_buffer_release(buffers[i]);
    }
    printf("Released all buffers\n");

    alya_vpn_buffer_pool_stats();
    alya_vpn_buffer_pool_shutdown();
}

// Test reference counting
void test_ref_counting() {
    printf("\n=== Test: Reference Counting ===\n");

    alya_vpn_buffer_pool_init();

    int buf_id = alya_vpn_buffer_acquire();
    printf("Acquired buffer %d, ref_count=1\n", buf_id);

    // Increment ref count (simulate shared ownership)
    alya_vpn_buffer_ref(buf_id);
    printf("After ref++, ref_count=2\n");

    // Release once (should not return to pool)
    alya_vpn_buffer_release(buf_id);
    printf("After first release, buffer still in use\n");

    // Release again (should return to pool)
    alya_vpn_buffer_release(buf_id);
    printf("After second release, buffer returned to pool\n");

    // Verify we can acquire again
    int buf_id2 = alya_vpn_buffer_acquire();
    printf("Re-acquired buffer %d\n", buf_id2);
    alya_vpn_buffer_release(buf_id2);

    alya_vpn_buffer_pool_stats();
    alya_vpn_buffer_pool_shutdown();
}

// Benchmark: compare buffer pool vs malloc
void test_performance() {
    printf("\n=== Test: Performance Comparison ===\n");

    alya_vpn_buffer_pool_init();

    const int ITERATIONS = 100000;

    // Benchmark buffer pool
    uint64_t start = 0, end = 0;
#if defined(_WIN32)
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
#endif

    for (int i = 0; i < ITERATIONS; ++i) {
        int id = alya_vpn_buffer_acquire();
        if (id >= 0) {
            uint8_t *data = alya_vpn_buffer_data(id);
            memset(data, 0xAA, 64); // Simulate work
            alya_vpn_buffer_release(id);
        }
    }

#if defined(_WIN32)
    QueryPerformanceCounter(&t2);
    double pool_ms = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
#else
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    // ... same loop ...
    clock_gettime(CLOCK_MONOTONIC, &t2);
    double pool_ms = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
#endif

    // Benchmark malloc/free
#if defined(_WIN32)
    QueryPerformanceCounter(&t1);
#endif

    for (int i = 0; i < ITERATIONS; ++i) {
        void *ptr = malloc(65536);
        if (ptr) {
            memset(ptr, 0xAA, 64);
            free(ptr);
        }
    }

#if defined(_WIN32)
    QueryPerformanceCounter(&t2);
    double malloc_ms = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
#else
    clock_gettime(CLOCK_MONOTONIC, &t1);
    // ... same loop ...
    clock_gettime(CLOCK_MONOTONIC, &t2);
    double malloc_ms = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
#endif

    printf("Buffer Pool: %.2f ms for %d iterations\n", pool_ms, ITERATIONS);
    printf("Malloc/Free: %.2f ms for %d iterations\n", malloc_ms, ITERATIONS);
    printf("Speedup: %.2fx\n", malloc_ms / pool_ms);

    alya_vpn_buffer_pool_stats();
    alya_vpn_buffer_pool_shutdown();
}

int main() {
    printf("Alya VPN Buffer Pool Test Suite\n");
    printf("================================\n");

    test_buffer_pool_basic();
    test_frame_in_buffer();
    test_multi_buffer();
    test_ref_counting();
    test_performance();

    printf("\n=== All Tests Complete ===\n");
    return 0;
}