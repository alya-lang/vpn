#ifndef ALYA_VPN_CRYPTO_H
#define ALYA_VPN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hashes a user passphrase into a 64-character hex key (SHA-256)
void alya_vpn_derive_key(const char *passphrase, char *out_key_hex);

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

// High-speed native envelope pack: generates nonce, encrypts, MACs, and formats "AV01..." frame
const char *alya_vpn_pack_frame(const char *key_hex, int msg_type, const char *payload, int payload_len);

// High-speed native envelope unpack: parses header, verifies MAC, decrypts, returns plaintext or ""
const char *alya_vpn_unpack_frame(const char *key_hex, const char *frame_line, int frame_len);

// Returns message type of last successfully unpacked frame, or 0 on error
int alya_vpn_unpack_frame_type(void);

// Formats a DATA frame payload natively: "channel_id|hex_data"
const char *alya_vpn_pack_data_payload(int channel_id, const char *hex_data);

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_CRYPTO_H

