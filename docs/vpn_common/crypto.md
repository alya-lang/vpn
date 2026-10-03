# Module `crypto`

Alya VPN - High-level Cryptography API
Wraps ChaCha20-Poly1305 AEAD and SHA-256 Key Derivation

## Table of Contents

- [Functions](#functions)
  - [`alloc_str`](#function-alloc_str)
  - [`vpn_derive_key`](#function-vpn_derive_key)
  - [`vpn_gen_nonce`](#function-vpn_gen_nonce)
  - [`vpn_encrypt`](#function-vpn_encrypt)
  - [`vpn_decrypt`](#function-vpn_decrypt)

## Functions

### Function `alloc_str`

```alya
function alloc_str(count)
```

Allocates a zero-initialized string buffer of exact byte length

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `count` | `auto` | `-` |

### Function `vpn_derive_key`

```alya
function vpn_derive_key(passphrase)
```

Derives a 32-byte (64 hex characters) symmetric encryption key from a passphrase

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `passphrase` | `auto` | `-` |

### Function `vpn_gen_nonce`

```alya
function vpn_gen_nonce()
```

Generates a random 12-byte (24 hex characters) cryptographic nonce

### Function `vpn_encrypt`

```alya
function vpn_encrypt(key_hex, nonce_hex, plaintext)
```

Encrypts plaintext payload using ChaCha20-Poly1305 AEAD
Returns tuple: cipher_hex (str), tag_hex (str), status (0 on success)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `key_hex` | `auto` | `-` |
| `nonce_hex` | `auto` | `-` |
| `plaintext` | `auto` | `-` |

### Function `vpn_decrypt`

```alya
function vpn_decrypt(key_hex, nonce_hex, cipher_hex, tag_hex)
```

Decrypts ciphertext and verifies Poly1305 integrity tag
Returns plaintext string on success, or null if authentication/tag check fails

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `key_hex` | `auto` | `-` |
| `nonce_hex` | `auto` | `-` |
| `cipher_hex` | `auto` | `-` |
| `tag_hex` | `auto` | `-` |
---

[↑ Workspace](../index.md)
