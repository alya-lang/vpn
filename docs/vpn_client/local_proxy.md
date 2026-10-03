# Module `local_proxy`

Alya VPN - Client Local SOCKS5 Proxy & Split Tunnel Engine
Intercepts outgoing application traffic, detects owning process, and routes traffic via VPN tunnel or local direct network

## Table of Contents

- [Functions](#functions)
  - [`parse_socks5_request`](#function-parse_socks5_request)
  - [`proc_display_name`](#function-proc_display_name)
  - [`udp_relay_select`](#function-udp_relay_select)
  - [`accept_one`](#function-accept_one)
  - [`dial_vpn_once`](#function-dial_vpn_once)
  - [`reconnect_vpn`](#function-reconnect_vpn)
  - [`vpn_run_client_proxy`](#function-vpn_run_client_proxy)

## Functions

### Function `parse_socks5_request`

```alya
function parse_socks5_request(client_sock)
```

Reads SOCKS5 target host and port from client request.
Returns: 1 + host + port (TCP CONNECT), 2 + "udp.associate" + 0
(UDP ASSOCIATE, control socket now owned by native code), 0 on failure.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `client_sock` | `auto` | `-` |

### Function `proc_display_name`

```alya
function proc_display_name(proc_name, peer_port)
```

Display label for logs: unresolved processes show their peer port
([unknown:51234]) so they can be correlated with netstat/lsof output.
Routing and host-inference keep using the raw "unknown" value.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `proc_name` | `auto` | `-` |
| `peer_port` | `auto` | `-` |

### Function `udp_relay_select`

```alya
function udp_relay_select(configured_port, proxy_port)
```

UDP relay port selection: an explicit configured port wins; 0/negative
falls back to proxy_port + 1 (the native bind adds ephemeral fallback).

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `configured_port` | `auto` | `-` |
| `proxy_port` | `auto` | `-` |

### Function `accept_one`

```alya
function accept_one(listen_sock)
```

Non-blocking single accept that never throws: polled socket or -1.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `listen_sock` | `auto` | `-` |

### Function `dial_vpn_once`

```alya
function dial_vpn_once(server_host, server_port)
```

Dials the VPN server once. net::tcp_connect throws on hard failures
(refused/unreachable) instead of returning -1, so the call is guarded
and every outcome funnels to a plain socket-or--1 contract.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `server_host` | `auto` | `-` |
| `server_port` | `auto` | `-` |

### Function `reconnect_vpn`

```alya
function reconnect_vpn(server_host, server_port, reconnect_attempts, reconnect_interval_ms)
```

Reconnect loop honoring attempts (0 = infinite) and interval.
Returns the new tunnel socket, or -1 when attempts run out / stopped.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `server_host` | `auto` | `-` |
| `server_port` | `auto` | `-` |
| `reconnect_attempts` | `auto` | `-` |
| `reconnect_interval_ms` | `auto` | `-` |

### Function `vpn_run_client_proxy`

```alya
function vpn_run_client_proxy(cfg)
```

Starts the local SOCKS5 proxy and routes traffic according to split-tunneling configuration

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `cfg` | `auto` | `-` |
---

[↑ Workspace](../index.md)
