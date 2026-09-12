#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// ============================================================================
// Internal Helpers: Hex Encoding & Decoding
// ============================================================================

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out, size_t max_out) {
    if (hex_len % 2 != 0 || hex_len / 2 > max_out) return -1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out_hex) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out_hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

// ============================================================================
// Secure Random Bytes
// ============================================================================

static void get_random_bytes(uint8_t *buf, size_t len) {
#if defined(_WIN32)
    static HCRYPTPROV s_hProv = 0;
    if (!s_hProv) {
        if (!CryptAcquireContextA(&s_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            CryptAcquireContextA(&s_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_SILENT);
        }
    }
    if (s_hProv && CryptGenRandom(s_hProv, (DWORD)len, buf)) {
        return;
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t res = read(fd, buf, len);
        close(fd);
        if (res == (ssize_t)len) return;
    }
#endif
    // Fallback pseudo-random
    srand((unsigned int)(time(NULL) ^ (uintptr_t)buf));
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

// ============================================================================
// SHA-256 Implementation (Self-Contained)
// ============================================================================

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_process_block(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + K256[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t buffer[64];
    size_t offset = 0;

    while (len >= 64) {
        sha256_process_block(state, data + offset);
        offset += 64;
        len -= 64;
    }

    memcpy(buffer, data + offset, len);
    buffer[len] = 0x80;
    size_t pad_pos = len + 1;

    if (pad_pos > 56) {
        memset(buffer + pad_pos, 0, 64 - pad_pos);
        sha256_process_block(state, buffer);
        pad_pos = 0;
    }
    memset(buffer + pad_pos, 0, 56 - pad_pos);

    uint64_t total_bits = (uint64_t)(offset + len) * 8;
    for (int i = 0; i < 8; ++i) {
        buffer[56 + i] = (uint8_t)((total_bits >> (56 - i * 8)) & 0xFF);
    }
    sha256_process_block(state, buffer);

    for (int i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)((state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = (uint8_t)((state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((state[i] >> 8) & 0xFF);
        out[i * 4 + 3] = (uint8_t)(state[i] & 0xFF);
    }
}

// ============================================================================
// ChaCha20 Stream Cipher (RFC 8439)
// ============================================================================

#define CHACHA20_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = rotr(d, 16); \
    c += d; b ^= c; b = rotr(b, 20); \
    a += b; d ^= a; d = rotr(d, 24); \
    c += d; b ^= c; b = rotr(b, 25);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    memcpy(out, in, sizeof(uint32_t) * 16);
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        CHACHA20_QUARTERROUND(out[0], out[4], out[8],  out[12]);
        CHACHA20_QUARTERROUND(out[1], out[5], out[9],  out[13]);
        CHACHA20_QUARTERROUND(out[2], out[6], out[10], out[14]);
        CHACHA20_QUARTERROUND(out[3], out[7], out[11], out[15]);
        // Diagonal rounds
        CHACHA20_QUARTERROUND(out[0], out[5], out[10], out[15]);
        CHACHA20_QUARTERROUND(out[1], out[6], out[11], out[12]);
        CHACHA20_QUARTERROUND(out[2], out[7], out[8],  out[13]);
        CHACHA20_QUARTERROUND(out[3], out[4], out[9],  out[14]);
    }
    for (int i = 0; i < 16; ++i) {
        out[i] += in[i];
    }
}

static void chacha20_xor(
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    const uint8_t *in,
    uint8_t *out,
    size_t len
) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // "expand 32-byte k"
        0, 0, 0, 0, 0, 0, 0, 0,
        counter, 0, 0, 0
    };

    // Load key into state[4..11]
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = ((uint32_t)key[i * 4]) |
                       ((uint32_t)key[i * 4 + 1] << 8) |
                       ((uint32_t)key[i * 4 + 2] << 16) |
                       ((uint32_t)key[i * 4 + 3] << 24);
    }
    // Load nonce into state[13..15]
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = ((uint32_t)nonce[i * 4]) |
                        ((uint32_t)nonce[i * 4 + 1] << 8) |
                        ((uint32_t)nonce[i * 4 + 2] << 16) |
                        ((uint32_t)nonce[i * 4 + 3] << 24);
    }

    uint32_t block[16];
    uint8_t key_stream[64];

    while (len > 0) {
        chacha20_block(block, state);
        state[12]++; // increment counter

        for (int i = 0; i < 16; ++i) {
            key_stream[i * 4]     = (uint8_t)(block[i] & 0xFF);
            key_stream[i * 4 + 1] = (uint8_t)((block[i] >> 8) & 0xFF);
            key_stream[i * 4 + 2] = (uint8_t)((block[i] >> 16) & 0xFF);
            key_stream[i * 4 + 3] = (uint8_t)((block[i] >> 24) & 0xFF);
        }

        size_t take = len < 64 ? len : 64;
        for (size_t i = 0; i < take; ++i) {
            *out++ = *in++ ^ key_stream[i];
        }
        len -= take;
    }
}

// ============================================================================
// Poly1305 MAC Implementation (RFC 8439)
// ============================================================================

static void poly1305_mac(
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t key[32],
    uint8_t tag[16]
) {
    // Standard Poly1305 130-bit evaluation modulo 2^130 - 5
    // Clamping r
    uint32_t r0 = (((uint32_t)key[0]) | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24)) & 0x0fffffff;
    uint32_t r1 = (((uint32_t)key[4]) | ((uint32_t)key[5] << 8) | ((uint32_t)key[6] << 16) | ((uint32_t)key[7] << 24)) & 0x0ffffffc;
    uint32_t r2 = (((uint32_t)key[8]) | ((uint32_t)key[9] << 8) | ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24)) & 0x0ffffffc;
    uint32_t r3 = (((uint32_t)key[12]) | ((uint32_t)key[13] << 8) | ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24)) & 0x0ffffffc;

    uint32_t s0 = ((uint32_t)key[16]) | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    uint32_t s1 = ((uint32_t)key[20]) | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    uint32_t s2 = ((uint32_t)key[24]) | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    uint32_t s3 = ((uint32_t)key[28]) | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);

    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    while (msg_len > 0) {
        size_t b_len = msg_len < 16 ? msg_len : 16;
        uint8_t block[17] = {0};
        memcpy(block, msg, b_len);
        block[b_len] = 0x01; // padding 1-bit

        uint32_t m0 = ((uint32_t)block[0]) | ((uint32_t)block[1] << 8) | ((uint32_t)block[2] << 16) | ((uint32_t)block[3] << 24);
        uint32_t m1 = ((uint32_t)block[4]) | ((uint32_t)block[5] << 8) | ((uint32_t)block[6] << 16) | ((uint32_t)block[7] << 24);
        uint32_t m2 = ((uint32_t)block[8]) | ((uint32_t)block[9] << 8) | ((uint32_t)block[10] << 16) | ((uint32_t)block[11] << 24);
        uint32_t m3 = ((uint32_t)block[12]) | ((uint32_t)block[13] << 8) | ((uint32_t)block[14] << 16) | ((uint32_t)block[15] << 24);
        uint32_t m4 = (uint32_t)block[16];

        h0 += m0 & 0x3ffffff;
        h1 += ((m0 >> 26) | (m1 << 6)) & 0x3ffffff;
        h2 += ((m1 >> 20) | (m2 << 12)) & 0x3ffffff;
        h3 += ((m2 >> 14) | (m3 << 18)) & 0x3ffffff;
        h4 += (m3 >> 8) | (m4 << 24);

        // Simple accumulator step
        uint64_t d0 = h0 * r0 + h1 * (5 * (r3 >> 2)) + h2 * (5 * (r2 >> 2)) + h3 * (5 * (r1 >> 2));
        uint64_t d1 = h0 * r1 + h1 * r0 + h2 * (5 * (r3 >> 2)) + h3 * (5 * (r2 >> 2));
        uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * (r3 >> 2));
        uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;

        h0 = d0 & 0x3ffffff;
        h1 = (d1 + (d0 >> 26)) & 0x3ffffff;
        h2 = (d2 + (d1 >> 26)) & 0x3ffffff;
        h3 = (d3 + (d2 >> 26)) & 0x3ffffff;
        h4 = (d3 >> 26);

        msg += b_len;
        msg_len -= b_len;
    }

    // Add s and output 16-byte tag
    uint64_t c = (h0 | (h1 << 26)) + s0;
    tag[0] = (uint8_t)c; tag[1] = (uint8_t)(c >> 8); tag[2] = (uint8_t)(c >> 16); tag[3] = (uint8_t)(c >> 24);

    c = ((h1 >> 6) | (h2 << 20)) + s1 + (c >> 32);
    tag[4] = (uint8_t)c; tag[5] = (uint8_t)(c >> 8); tag[6] = (uint8_t)(c >> 16); tag[7] = (uint8_t)(c >> 24);

    c = ((h2 >> 12) | (h3 << 14)) + s2 + (c >> 32);
    tag[8] = (uint8_t)c; tag[9] = (uint8_t)(c >> 8); tag[10] = (uint8_t)(c >> 16); tag[11] = (uint8_t)(c >> 24);

    c = ((h3 >> 18) | (h4 << 8)) + s3 + (c >> 32);
    tag[12] = (uint8_t)c; tag[13] = (uint8_t)(c >> 8); tag[14] = (uint8_t)(c >> 16); tag[15] = (uint8_t)(c >> 24);
}

// ============================================================================
// Public API Implementations
// ============================================================================

static char s_session_key_hex[65] = {0};
static uint8_t s_session_key_bin[32] = {0};
static int s_has_session_key = 0;

void alya_vpn_derive_key(const char *passphrase, char *out_key_hex) {
    if (!passphrase) return;
    uint8_t hash[32];
    sha256_hash((const uint8_t *)passphrase, strlen(passphrase), hash);
    if (out_key_hex) {
        bytes_to_hex(hash, 32, out_key_hex);
    }
    bytes_to_hex(hash, 32, s_session_key_hex);
    memcpy(s_session_key_bin, hash, 32);
    s_has_session_key = 1;
}

void alya_vpn_set_session_key(const char *key_hex) {
    if (!key_hex) return;
    if (strlen(key_hex) >= 64) {
        memcpy(s_session_key_hex, key_hex, 64);
        s_session_key_hex[64] = '\0';
        if (hex_to_bytes(s_session_key_hex, 64, s_session_key_bin, 32) == 0) {
            s_has_session_key = 1;
        }
    }
}

void alya_vpn_set_session_passphrase(const char *passphrase) {
    if (!passphrase) return;
    alya_vpn_derive_key(passphrase, s_session_key_hex);
    s_session_key_hex[64] = '\0';
    if (hex_to_bytes(s_session_key_hex, 64, s_session_key_bin, 32) == 0) {
        s_has_session_key = 1;
    }
}

const char *alya_vpn_get_session_key(void) {
    return s_session_key_hex;
}

void alya_vpn_gen_nonce(char *out_nonce_hex) {
    if (!out_nonce_hex) return;
    uint8_t nonce[12];
    get_random_bytes(nonce, 12);
    bytes_to_hex(nonce, 12, out_nonce_hex);
}

int alya_vpn_encrypt(
    const char *key_hex,
    const char *nonce_hex,
    const char *plaintext,
    int plain_len,
    char *out_cipher_hex,
    char *out_tag_hex
) {
    if (!plaintext || plain_len < 0 || !out_cipher_hex || !out_tag_hex) {
        return -2;
    }

    uint8_t key[32];
    uint8_t nonce[12];
    if (!key_hex || hex_to_bytes(key_hex, 64, key, 32) != 0) {
        if (s_has_session_key) {
            memcpy(key, s_session_key_bin, 32);
        } else {
            return -2;
        }
    }

    if (!nonce_hex || hex_to_bytes(nonce_hex, 24, nonce, 12) != 0) {
        get_random_bytes(nonce, 12);
    }

    // 1. One-time Poly1305 key generation via ChaCha20 block 0
    uint8_t poly_key[32] = {0};
    chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);

    // 2. Encrypt plaintext starting at counter 1
    uint8_t *ciphertext = (uint8_t *)malloc((size_t)plain_len + 1);
    if (!ciphertext && plain_len > 0) return -2;

    chacha20_xor(key, nonce, 1, (const uint8_t *)plaintext, ciphertext, (size_t)plain_len);

    // 3. Compute Poly1305 MAC tag
    uint8_t tag[16];
    poly1305_mac(ciphertext, (size_t)plain_len, poly_key, tag);

    // 4. Output hex
    bytes_to_hex(ciphertext, (size_t)plain_len, out_cipher_hex);
    bytes_to_hex(tag, 16, out_tag_hex);

    free(ciphertext);
    return 0;
}

int alya_vpn_decrypt(
    const char *key_hex,
    const char *nonce_hex,
    const char *cipher_hex,
    int cipher_len,
    const char *tag_hex,
    char *out_plain
) {
    if (!cipher_hex || cipher_len < 0 || !tag_hex || !out_plain) {
        return -2;
    }

    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t expected_tag[16];

    if (!key_hex || hex_to_bytes(key_hex, 64, key, 32) != 0) {
        if (s_has_session_key) {
            memcpy(key, s_session_key_bin, 32);
        } else {
            return -2;
        }
    }

    if (!nonce_hex || hex_to_bytes(nonce_hex, 24, nonce, 12) != 0 ||
        hex_to_bytes(tag_hex, 32, expected_tag, 16) != 0) {
        return -2;
    }

    size_t raw_len = (size_t)cipher_len / 2;
    uint8_t *ciphertext = (uint8_t *)malloc(raw_len + 1);
    if (!ciphertext && raw_len > 0) return -2;

    if (hex_to_bytes(cipher_hex, (size_t)cipher_len, ciphertext, raw_len) != 0) {
        free(ciphertext);
        return -2;
    }

    // 1. One-time Poly1305 key generation via ChaCha20 block 0
    uint8_t poly_key[32] = {0};
    chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);

    // 2. Compute and verify Poly1305 MAC
    uint8_t computed_tag[16];
    poly1305_mac(ciphertext, raw_len, poly_key, computed_tag);

    // Constant-time tag check
    int diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (computed_tag[i] ^ expected_tag[i]);
    }

    if (diff != 0) {
        free(ciphertext);
        return -1; // Authentication Failed!
    }

    // 3. Decrypt ciphertext starting at counter 1
    chacha20_xor(key, nonce, 1, ciphertext, (uint8_t *)out_plain, raw_len);
    out_plain[raw_len] = '\0';

    free(ciphertext);
    return 0;
}

static char s_frame_buf[131072];
static char s_plain_buf[65536];
static int s_last_unpack_type = 0;

int alya_vpn_unpack_frame_type(void) {
    return s_last_unpack_type;
}

const char *alya_vpn_pack_frame(const char *key_hex, int msg_type, const char *payload, int payload_len) {
    if (msg_type <= 0 || payload_len < 0 || payload_len > 32768) {
        return "";
    }

    uint8_t key[32];
    if (!key_hex || strlen(key_hex) < 64 || hex_to_bytes(key_hex, 64, key, 32) != 0) {
        if (s_has_session_key) {
            memcpy(key, s_session_key_bin, 32);
        } else {
            return "";
        }
    }

    // Generate random 12-byte nonce
    uint8_t nonce[12];
    char nonce_hex[25];
    alya_vpn_gen_nonce(nonce_hex);
    hex_to_bytes(nonce_hex, 24, nonce, 12);

    // 1. One-time Poly1305 key generation via ChaCha20 block 0
    uint8_t poly_key[32] = {0};
    chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);

    // 2. Encrypt plaintext starting at counter 1
    uint8_t ciphertext[32768];
    if (payload_len > 0 && payload) {
        chacha20_xor(key, nonce, 1, (const uint8_t *)payload, ciphertext, (size_t)payload_len);
    }

    // 3. Compute Poly1305 MAC tag
    uint8_t tag[16];
    poly1305_mac(ciphertext, (size_t)payload_len, poly_key, tag);

    // 4. Build frame: "AV01" + type_hex(2) + nonce_hex(24) + tag_hex(32) + cipher_hex(2*len) + "\n"
    static const char hex_chars[] = "0123456789abcdef";
    s_frame_buf[0] = 'A';
    s_frame_buf[1] = 'V';
    s_frame_buf[2] = '0';
    s_frame_buf[3] = '1';
    s_frame_buf[4] = hex_chars[(msg_type >> 4) & 0x0F];
    s_frame_buf[5] = hex_chars[msg_type & 0x0F];
    memcpy(&s_frame_buf[6], nonce_hex, 24);
    bytes_to_hex(tag, 16, &s_frame_buf[30]);
    bytes_to_hex(ciphertext, (size_t)payload_len, &s_frame_buf[62]);

    int total_len = 62 + (payload_len * 2);
    s_frame_buf[total_len] = '\n';
    s_frame_buf[total_len + 1] = '\0';

    return s_frame_buf;
}

const char *alya_vpn_unpack_frame(const char *key_hex, const char *frame_line, int frame_len) {
    s_last_unpack_type = 0;
    if (!frame_line || frame_len < 62) return "";

    // Strip trailing \r / \n
    while (frame_len > 0 && (frame_line[frame_len - 1] == '\n' || frame_line[frame_len - 1] == '\r')) {
        frame_len--;
    }
    if (frame_len < 62) return "";

    if (frame_line[0] != 'A' || frame_line[1] != 'V' || frame_line[2] != '0' || frame_line[3] != '1') {
        return "";
    }

    uint8_t key[32];
    if (!key_hex || hex_to_bytes(key_hex, 64, key, 32) != 0) {
        if (s_has_session_key) {
            memcpy(key, s_session_key_bin, 32);
        } else {
            return "";
        }
    }

    // Message type
    uint8_t type_byte = 0;
    if (hex_to_bytes(&frame_line[4], 2, &type_byte, 1) != 0) return "";

    // Nonce
    uint8_t nonce[12];
    if (hex_to_bytes(&frame_line[6], 24, nonce, 12) != 0) return "";

    // Expected tag
    uint8_t expected_tag[16];
    if (hex_to_bytes(&frame_line[30], 32, expected_tag, 16) != 0) return "";

    // Ciphertext
    int cipher_hex_len = frame_len - 62;
    if (cipher_hex_len % 2 != 0) return "";
    int raw_len = cipher_hex_len / 2;
    if (raw_len > (int)sizeof(s_plain_buf) - 8) return "";

    uint8_t ciphertext[32768];
    if (raw_len > (int)sizeof(ciphertext)) return "";
    if (raw_len > 0) {
        if (hex_to_bytes(&frame_line[62], (size_t)cipher_hex_len, ciphertext, (size_t)raw_len) != 0) {
            return "";
        }
    }

    // 1. One-time Poly1305 key generation via ChaCha20 block 0
    uint8_t poly_key[32] = {0};
    chacha20_xor(key, nonce, 0, poly_key, poly_key, 32);

    // 2. Compute and verify Poly1305 MAC
    uint8_t computed_tag[16];
    poly1305_mac(ciphertext, (size_t)raw_len, poly_key, computed_tag);

    int diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (computed_tag[i] ^ expected_tag[i]);
    }
    if (diff != 0) {
        return ""; // MAC verification failed!
    }

    // 3. Decrypt ciphertext starting at counter 1
    if (raw_len > 0) {
        chacha20_xor(key, nonce, 1, ciphertext, (uint8_t *)s_plain_buf, (size_t)raw_len);
    }
    s_plain_buf[raw_len] = '\0';
    s_last_unpack_type = (int)type_byte;

    return s_plain_buf;
}

static char s_data_payload_buf[65536];

const char *alya_vpn_pack_data_payload(int channel_id, const char *hex_data) {
    if (!hex_data) hex_data = "";
    snprintf(s_data_payload_buf, sizeof(s_data_payload_buf), "%d|%s", channel_id, hex_data);
    return s_data_payload_buf;
}

