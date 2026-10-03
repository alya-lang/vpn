# Module `main`

Alya VPN - Next-Gen Split-Tunneling Encrypted VPN
CLI Entry point supporting Server, Client (SOCKS5 + Split Tunneling), and Diagnostic commands

## Table of Contents

- [Functions](#functions)
  - [`print_banner`](#function-print_banner)
  - [`print_usage`](#function-print_usage)
  - [`strip_val`](#function-strip_val)
  - [`load_client_config`](#function-load_client_config)
  - [`load_server_config`](#function-load_server_config)
  - [`main`](#function-main)

## Functions

### Function `print_banner`

```alya
function print_banner()
```

### Function `print_usage`

```alya
function print_usage()
```

### Function `strip_val`

```alya
function strip_val(s)
```

Trims whitespace and quotes from start and end of string (preserves spaces inside)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |

### Function `load_client_config`

```alya
function load_client_config(config_path)
```

Loads client configuration from config/client.toml

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `config_path` | `auto` | `-` |

### Function `load_server_config`

```alya
function load_server_config(config_path)
```

Loads server configuration from config/server.toml

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `config_path` | `auto` | `-` |

### Function `main`

```alya
function main()
```
---

[↑ Workspace](../index.md)
