# Module `resolver`

Alya VPN - Process Resolver
Maps local client socket ports to process executable names using OS-level network tables

## Table of Contents

- [Functions](#functions)
  - [`extract_c_string`](#function-extract_c_string)
  - [`resolve_tcp_process`](#function-resolve_tcp_process)
  - [`resolve_udp_process`](#function-resolve_udp_process)

## Functions

### Function `extract_c_string`

```alya
function extract_c_string(buf)
```

Extracts null-terminated C string from buffer

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `buf` | `auto` | `-` |

### Function `resolve_tcp_process`

```alya
function resolve_tcp_process(local_port)
```

Resolves TCP local port to process name (e.g. "Discord.exe", "chrome.exe")
Returns lowercase process name, or empty string if not found or system process

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `local_port` | `auto` | `-` |

### Function `resolve_udp_process`

```alya
function resolve_udp_process(local_port)
```

Resolves UDP local port to process name

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `local_port` | `auto` | `-` |
---

[↑ Workspace](../index.md)
