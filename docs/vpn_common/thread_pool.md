# Module `thread_pool`

Alya VPN - Thread Pool Wrapper
High-level API for thread pool operations from Alya

## Table of Contents

- [Functions](#functions)
  - [`WORK_CRYPTO_ENCRYPT`](#function-work_crypto_encrypt)
  - [`WORK_CRYPTO_DECRYPT`](#function-work_crypto_decrypt)
  - [`WORK_IO_READ`](#function-work_io_read)
  - [`WORK_IO_WRITE`](#function-work_io_write)
  - [`WORK_IO_ACCEPT`](#function-work_io_accept)
  - [`thread_pool_init`](#function-thread_pool_init)
  - [`thread_pool_shutdown`](#function-thread_pool_shutdown)
  - [`thread_pool_is_initialized`](#function-thread_pool_is_initialized)
  - [`thread_pool_drain`](#function-thread_pool_drain)
  - [`thread_pool_submit_crypto_encrypt`](#function-thread_pool_submit_crypto_encrypt)
  - [`thread_pool_submit_crypto_decrypt`](#function-thread_pool_submit_crypto_decrypt)
  - [`thread_pool_submit_io_read`](#function-thread_pool_submit_io_read)
  - [`thread_pool_submit_io_write`](#function-thread_pool_submit_io_write)
  - [`thread_pool_submit_io_accept`](#function-thread_pool_submit_io_accept)
  - [`thread_pool_assign_channel_worker`](#function-thread_pool_assign_channel_worker)
  - [`thread_pool_get_channel_worker`](#function-thread_pool_get_channel_worker)
  - [`thread_pool_auto_assign_channel`](#function-thread_pool_auto_assign_channel)

## Functions

### Function `WORK_CRYPTO_ENCRYPT`

```alya
function WORK_CRYPTO_ENCRYPT()
```

Work types

### Function `WORK_CRYPTO_DECRYPT`

```alya
function WORK_CRYPTO_DECRYPT()
```

### Function `WORK_IO_READ`

```alya
function WORK_IO_READ()
```

### Function `WORK_IO_WRITE`

```alya
function WORK_IO_WRITE()
```

### Function `WORK_IO_ACCEPT`

```alya
function WORK_IO_ACCEPT()
```

### Function `thread_pool_init`

```alya
function thread_pool_init(crypto_workers, io_workers)
```

Initialize thread pool
crypto_workers: number of crypto workers (0 = auto)
io_workers: number of I/O workers (0 = auto)
Returns 0 on success

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `crypto_workers` | `auto` | `-` |
| `io_workers` | `auto` | `-` |

### Function `thread_pool_shutdown`

```alya
function thread_pool_shutdown()
```

Shutdown thread pool

### Function `thread_pool_is_initialized`

```alya
function thread_pool_is_initialized()
```

Check if thread pool is initialized

### Function `thread_pool_drain`

```alya
function thread_pool_drain()
```

Wait for all pending work to complete

### Function `thread_pool_submit_crypto_encrypt`

```alya
function thread_pool_submit_crypto_encrypt(buffer_id, msg_type, payload_len, channel_id, key_hex)
```

Submit crypto encryption work
buffer_id: buffer containing plaintext
msg_type: message type for frame
payload_len: length of plaintext
channel_id: associated channel
key_hex: optional key (uses session key if empty)
Returns 0 on success, -1 if queue full

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `buffer_id` | `auto` | `-` |
| `msg_type` | `auto` | `-` |
| `payload_len` | `auto` | `-` |
| `channel_id` | `auto` | `-` |
| `key_hex` | `auto` | `-` |

### Function `thread_pool_submit_crypto_decrypt`

```alya
function thread_pool_submit_crypto_decrypt(buffer_id, frame_len, channel_id, key_hex)
```

Submit crypto decryption work
buffer_id: buffer containing frame
frame_len: total frame length
channel_id: associated channel
key_hex: optional key (uses session key if empty)
Returns 0 on success, -1 if queue full

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `buffer_id` | `auto` | `-` |
| `frame_len` | `auto` | `-` |
| `channel_id` | `auto` | `-` |
| `key_hex` | `auto` | `-` |

### Function `thread_pool_submit_io_read`

```alya
function thread_pool_submit_io_read(sock, buffer_id, len, channel_id)
```

Submit I/O read work
sock: socket descriptor
buffer_id: buffer to read into
len: max bytes to read
channel_id: associated channel
Returns 0 on success, -1 if queue full

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `sock` | `auto` | `-` |
| `buffer_id` | `auto` | `-` |
| `len` | `auto` | `-` |
| `channel_id` | `auto` | `-` |

### Function `thread_pool_submit_io_write`

```alya
function thread_pool_submit_io_write(sock, buffer_id, offset, len, channel_id)
```

Submit I/O write work
sock: socket descriptor
buffer_id: buffer to write from
offset: offset in buffer
len: bytes to write
channel_id: associated channel
Returns 0 on success, -1 if queue full

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `sock` | `auto` | `-` |
| `buffer_id` | `auto` | `-` |
| `offset` | `auto` | `-` |
| `len` | `auto` | `-` |
| `channel_id` | `auto` | `-` |

### Function `thread_pool_submit_io_accept`

```alya
function thread_pool_submit_io_accept(sock, buffer_id, channel_id)
```

Submit I/O accept work
sock: listening socket
buffer_id: unused (can be -1)
channel_id: associated channel
Returns 0 on success, -1 if queue full

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `sock` | `auto` | `-` |
| `buffer_id` | `auto` | `-` |
| `channel_id` | `auto` | `-` |

### Function `thread_pool_assign_channel_worker`

```alya
function thread_pool_assign_channel_worker(channel_id, worker_id)
```

Assign channel to I/O worker for affinity

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |
| `worker_id` | `auto` | `-` |

### Function `thread_pool_get_channel_worker`

```alya
function thread_pool_get_channel_worker(channel_id)
```

Get assigned I/O worker for channel

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |

### Function `thread_pool_auto_assign_channel`

```alya
function thread_pool_auto_assign_channel(channel_id, io_worker_count)
```

Auto-assign channel to I/O worker using round-robin

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |
| `io_worker_count` | `auto` | `-` |
---

[← All modules](index.md) · [↑ Workspace](../index.md)
