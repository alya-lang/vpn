# Module `forwarder`

Alya VPN - Server Engine and Traffic Forwarder
Listens for client tunnels, authenticates frames, and forwards payload traffic to destination hosts

## Table of Contents

- [Functions](#functions)
  - [`server_poll_accept`](#function-server_poll_accept)
  - [`vpn_run_server`](#function-vpn_run_server)
  - [`vpn_client_thread`](#function-vpn_client_thread)
  - [`vpn_handle_client`](#function-vpn_handle_client)
  - [`vpn_process_client_message`](#function-vpn_process_client_message)

## Functions

### Function `server_poll_accept`

```alya
function server_poll_accept(listen_sock, timeout_ms, allowed_clients, max_clients, log_client_events, client_thread_handler)
```

Polls one listen socket and dispatches a single pending client connection.
Returns 1 when a connection was accepted, else 0.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `listen_sock` | `auto` | `-` |
| `timeout_ms` | `auto` | `-` |
| `allowed_clients` | `auto` | `-` |
| `max_clients` | `auto` | `-` |
| `log_client_events` | `auto` | `-` |
| `client_thread_handler` | `auto` | `-` |

### Function `vpn_run_server`

```alya
function vpn_run_server(cfg, client_thread_handler)
```

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `cfg` | `auto` | `-` |
| `client_thread_handler` | `auto` | `-` |

### Function `vpn_client_thread`

```alya
function vpn_client_thread(client_sock)
```

Thread entry point: passed from main as server::vpn_client_thread.
Each call runs in its own OS thread with an isolated Alya heap.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `client_sock` | `auto` | `-` |

### Function `vpn_handle_client`

```alya
function vpn_handle_client(client_sock, _session_key)
```

Handles a single connected client session

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `client_sock` | `auto` | `-` |
| `_session_key` | `auto` | `-` |

### Function `vpn_process_client_message`

```alya
function vpn_process_client_message(client_sock, session_key, msg_type, payload)
```

Processes decrypted message from client (for backward compatibility)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `client_sock` | `auto` | `-` |
| `session_key` | `auto` | `-` |
| `msg_type` | `auto` | `-` |
| `payload` | `auto` | `-` |
---

[← All modules](index.md) · [↑ Workspace](../index.md)
