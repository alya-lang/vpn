# Module `protocol`

Alya VPN - Protocol Specification and Frame Serialization
Pure Alya implementation without external dependencies

## Table of Contents

- [Enums](#enums)
  - [`ForwardProtocol`](#enum-forwardprotocol)
- [Functions](#functions)
  - [`msg_handshake_req`](#function-msg_handshake_req)
  - [`msg_handshake_resp`](#function-msg_handshake_resp)
  - [`msg_connect_req`](#function-msg_connect_req)
  - [`msg_connect_resp`](#function-msg_connect_resp)
  - [`msg_data`](#function-msg_data)
  - [`msg_close`](#function-msg_close)
  - [`msg_ping`](#function-msg_ping)
  - [`msg_pong`](#function-msg_pong)
  - [`proto_tcp`](#function-proto_tcp)
  - [`proto_udp`](#function-proto_udp)
  - [`parse_forward_protocol`](#function-parse_forward_protocol)
  - [`status_ok`](#function-status_ok)
  - [`status_auth_failed`](#function-status_auth_failed)
  - [`status_connect_failed`](#function-status_connect_failed)
  - [`status_error`](#function-status_error)
  - [`split_string`](#function-split_string)
  - [`find_char`](#function-find_char)
  - [`parse_number`](#function-parse_number)
  - [`hex_char_val`](#function-hex_char_val)
  - [`hex_to_byte`](#function-hex_to_byte)
  - [`byte_to_hex`](#function-byte_to_hex)
  - [`pack_connect_req_payload`](#function-pack_connect_req_payload)
  - [`unpack_connect_req_payload`](#function-unpack_connect_req_payload)
  - [`pack_connect_resp_payload`](#function-pack_connect_resp_payload)
  - [`unpack_connect_resp_payload`](#function-unpack_connect_resp_payload)
  - [`pack_data_payload`](#function-pack_data_payload)
  - [`unpack_data_payload`](#function-unpack_data_payload)
  - [`pack_close_payload`](#function-pack_close_payload)
  - [`unpack_close_payload`](#function-unpack_close_payload)
  - [`pack_frame`](#function-pack_frame)
  - [`unpack_frame`](#function-unpack_frame)

## Enums

### Enum `ForwardProtocol`

Forward protocol modes: which forwarded payload types client and server
agree to carry. Integer-backed (1/2/3) for the native FFI boundary.

| Variant | Explicit Value |
|:---|:---|
| `TcpOnly` | `1` |
| `UdpOnly` | `2` |
| `Both` | `3` |

## Functions

### Function `msg_handshake_req`

```alya
function msg_handshake_req()
```

Message Types

### Function `msg_handshake_resp`

```alya
function msg_handshake_resp()
```

### Function `msg_connect_req`

```alya
function msg_connect_req()
```

### Function `msg_connect_resp`

```alya
function msg_connect_resp()
```

### Function `msg_data`

```alya
function msg_data()
```

### Function `msg_close`

```alya
function msg_close()
```

### Function `msg_ping`

```alya
function msg_ping()
```

### Function `msg_pong`

```alya
function msg_pong()
```

### Function `proto_tcp`

```alya
function proto_tcp()
```

Transport Protocols

### Function `proto_udp`

```alya
function proto_udp()
```

### Function `parse_forward_protocol`

```alya
function parse_forward_protocol(s) -> ForwardProtocol
```

Parses a "protocol" config value ("tcp" / "udp" / "both", case-insensitive).
Unknown values fall back to Both.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |

**Returns:** `ForwardProtocol`

### Function `status_ok`

```alya
function status_ok()
```

Status Codes

### Function `status_auth_failed`

```alya
function status_auth_failed()
```

### Function `status_connect_failed`

```alya
function status_connect_failed()
```

### Function `status_error`

```alya
function status_error()
```

### Function `split_string`

```alya
function split_string(s, delim)
```

Splits string by single character delimiter

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |
| `delim` | `auto` | `-` |

### Function `find_char`

```alya
function find_char(s, target_ch)
```

Finds index of substring

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |
| `target_ch` | `auto` | `-` |

### Function `parse_number`

```alya
function parse_number(s)
```

Parses string to integer (supports basic positive decimal)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |

### Function `hex_char_val`

```alya
function hex_char_val(ch)
```

Converts 1 hex character to 0..15

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `ch` | `auto` | `-` |

### Function `hex_to_byte`

```alya
function hex_to_byte(h)
```

Converts 2 hex characters to byte (0..255)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `h` | `auto` | `-` |

### Function `byte_to_hex`

```alya
function byte_to_hex(b)
```

Converts byte (0..255) to 2-digit hex string

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `b` | `auto` | `-` |

### Function `pack_connect_req_payload`

```alya
function pack_connect_req_payload(channel_id, proto, target_host, target_port)
```

Serializes CONNECT_REQ payload: "channel_id|proto|host|port"

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |
| `proto` | `auto` | `-` |
| `target_host` | `auto` | `-` |
| `target_port` | `auto` | `-` |

### Function `unpack_connect_req_payload`

```alya
function unpack_connect_req_payload(payload)
```

Parses CONNECT_REQ payload: returns ok, channel_id, proto, target_host, target_port

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `payload` | `auto` | `-` |

### Function `pack_connect_resp_payload`

```alya
function pack_connect_resp_payload(channel_id, status, message)
```

Serializes CONNECT_RESP payload: "channel_id|status|message"

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |
| `status` | `auto` | `-` |
| `message` | `auto` | `-` |

### Function `unpack_connect_resp_payload`

```alya
function unpack_connect_resp_payload(payload)
```

Parses CONNECT_RESP payload: returns ok, channel_id, status, message

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `payload` | `auto` | `-` |

### Function `pack_data_payload`

```alya
function pack_data_payload(channel_id, raw_data)
```

Serializes DATA payload: "channel_id|data"

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |
| `raw_data` | `auto` | `-` |

### Function `unpack_data_payload`

```alya
function unpack_data_payload(payload)
```

Parses DATA payload: returns ok, channel_id, data_str

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `payload` | `auto` | `-` |

### Function `pack_close_payload`

```alya
function pack_close_payload(channel_id, reason)
```

Serializes CLOSE payload: "channel_id|reason"

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `channel_id` | `auto` | `-` |
| `reason` | `auto` | `-` |

### Function `unpack_close_payload`

```alya
function unpack_close_payload(payload)
```

Parses CLOSE payload: returns ok, channel_id, reason

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `payload` | `auto` | `-` |

### Function `pack_frame`

```alya
function pack_frame(session_key, msg_type, plaintext_payload)
```

Packs an authenticated and encrypted envelope frame
Envelope structure:
[Magic: 2 chars "AV"] [Version: 2 hex "01"] [Type: 2 hex] [Nonce: 24 hex] [Tag: 32 hex] [Cipher_Hex: N*2 chars] \n

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `session_key` | `auto` | `-` |
| `msg_type` | `auto` | `-` |
| `plaintext_payload` | `auto` | `-` |

### Function `unpack_frame`

```alya
function unpack_frame(session_key, frame_line)
```

Unpacks and authenticates an incoming frame
Returns tuple: msg_type, plaintext (or 0, null on failure)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `session_key` | `auto` | `-` |
| `frame_line` | `auto` | `-` |
---

[↑ Workspace](../index.md)
