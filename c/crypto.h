#ifndef ALYA_VPN_CRYPTO_H
#define ALYA_VPN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hashes a user passphrase into a 64-character hex key (SHA-256)
void alya_vpn_derive_key(const char *passphrase, char *out_key_hex);

// Session passphrase / key cache (stored in native C memory, immune to Alya bump allocator wrap)
void alya_vpn_set_session_passphrase(const char *passphrase);
void alya_vpn_set_session_key(const char *key_hex);
const char *alya_vpn_get_session_key(void);

// Generates a random 24-character hex nonce (12 bytes)
void alya_vpn_gen_nonce(char *out_nonce_hex);

// Encrypts plaintext using ChaCha20-Poly1305
// Inputs: key_hex (64 hex chars), nonce_hex (24 hex chars), plaintext (raw string), plain_len
// Outputs: out_cipher_hex (hex representation of ciphertext, 2 * plain_len chars), out_tag_hex (32 hex chars)
// Returns 0 on success, negative on error.
int alya_vpn_encrypt(
    const char *key_hex,
    const char *nonce_hex,
    const char *plaintext,
    int plain_len,
    char *out_cipher_hex,
    char *out_tag_hex
);

// Decrypts ciphertext and verifies Poly1305 authentication tag
// Returns 0 on success (verified), -1 on authentication failure, -2 on format error.
int alya_vpn_decrypt(
    const char *key_hex,
    const char *nonce_hex,
    const char *cipher_hex,
    int cipher_len,
    const char *tag_hex,
    char *out_plain
);

// ============================================================================
// BINARY FRAME FORMAT (New - replaces text-based AV01 hex format)
// ============================================================================
//
// Frame structure:
//   [Magic: 2 bytes 'A','V'] [Version: 1 byte 0x01] [Type: 1 byte] [Nonce: 12 bytes] [Tag: 16 bytes] [Ciphertext: N bytes]
//   Total header: 32 bytes, Payload: N bytes = 1x overhead vs 2x for hex format
//
// Legacy text format (deprecated but kept for backward compatibility):
//   "AV01" + type_hex(2) + nonce_hex(24) + tag_hex(32) + cipher_hex(2*N) + "\n"
//   Header: 62 chars + 2*N chars = ~2x payload size

// High-speed native envelope pack (BINARY): generates nonce, encrypts, MACs, and formats binary frame
// Returns pointer to static thread-local buffer, or "" on error.
// Output buffer layout: [2B magic][1B version][1B type][12B nonce][16B tag][N ciphertext]
const uint8_t *alya_vpn_pack_frame_bin(
    const char *key_hex,
    int msg_type,
    const char *payload,
    int payload_len,
    int *out_frame_len
);

// High-speed native envelope unpack (BINARY): parses header, verifies MAC, decrypts
// Returns pointer to static thread-local plaintext buffer, or NULL on error.
// Input frame must be binary format as produced by alya_vpn_pack_frame_bin
const char *alya_vpn_unpack_frame_bin(
    const char *key_hex,
    const uint8_t *frame,
    int frame_len
);

// Returns message type of last successfully unpacked binary frame, or 0 on error
int alya_vpn_unpack_frame_bin_type(void);

// Legacy text-based frame functions (kept for backward compatibility)
const char *alya_vpn_pack_frame(const char *key_hex, int msg_type, const char *payload, int payload_len);
const char *alya_vpn_unpack_frame(const char *key_hex, const char *frame_line, int frame_len);
int alya_vpn_unpack_frame_type(void);

// Formats a DATA frame payload natively: "channel_id|hex_data"
const char *alya_vpn_pack_data_payload(int channel_id, const char *hex_data);

// ============================================================================
// Internal Crypto Functions (exposed for buffer_pool.c zero-copy framing)
// ============================================================================

// Generate random bytes directly into buffer (no hex round-trip)
void alya_vpn_get_random_bytes(uint8_t *buf, size_t len);

// ChaCha20 XOR stream cipher (core primitive)
void alya_vpn_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);

// Poly1305 MAC computation
void alya_vpn_poly1305_mac(const uint8_t *msg, size_t msg_len,
                            const uint8_t key[32], uint8_t tag[16]);

// Check if session key is cached
int alya_vpn_has_session_key(void);

// Get cached session key binary (32 bytes)
const uint8_t *alya_vpn_get_session_key_bin(void);

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_CRYPTO_H