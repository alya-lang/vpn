#ifndef ALYA_VPN_PROC_RESOLVER_H
#define ALYA_VPN_PROC_RESOLVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Resolves the executable filename (e.g. "Discord.exe" or "discord")
// of the process that owns the specified local TCP port.
// Writes the filename to out_name (up to max_len bytes).
// Returns 1 on success, 0 on failure / process not found.
int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len);

// NEW: Resolves the process by matching BOTH the proxy's local listening port
// AND the peer's remote (ephemeral) port. This is required because the VPN
// proxy accepts multiple client connections on the same local port, and each
// connection has a unique peer remote port. The TCP table entry for an accepted
// connection has dwLocalPort == proxy_local_port and dwRemotePort == peer_remote_port.
// Returns 1 on success, 0 on failure / process not found.
int alya_vpn_get_process_by_peer_port(int proxy_local_port, int peer_remote_port, char *out_name, int max_len);

// Resolves executable name for a local UDP port.
int alya_vpn_get_udp_process_by_port(int local_port, char *out_name, int max_len);

// Performs standard SOCKS5 handshake directly over socket.
// Fills out_host with target hostname or IPv4 string.
// Returns target_port (> 0) on success, or -1 on failure.
int alya_vpn_socks5_handshake(int client_sock, char *out_host, int max_host_len);

// Receives raw binary data from socket and encodes it directly to a null-terminated hex string in static buffer.
// Returns pointer to hex string (or "" on EOF/error).
const char *alya_vpn_sock_recv_hex(int sock, int max_bytes);

// Decodes a hex string back to raw binary and sends it over socket.
// Returns number of binary bytes sent (< 0 on error).
int alya_vpn_sock_send_hex(int sock, const char *hex_str, int hex_len);

// ============================================================================
// Split-Tunneling Routing Engine (Native C, immune to cyclic buffer wrap)
// ============================================================================

// Sets split-tunneling routing mode and application list
// mode: 0 = ALL, 1 = INCLUDE (whitelist), 2 = EXCLUDE (blacklist)
// apps_csv: comma-separated app names or patterns (e.g. "chrome.exe,curl.exe,discord")
void alya_vpn_set_routing(int mode, const char *apps_csv);

// Adds a single app name to the routing list.
// Use this instead of building a CSV in Alya to avoid array-element pointer-address bug.
void alya_vpn_add_routing_app(const char *app_name);

// Resolves process from proxy local port AND peer remote port and determines
// whether it should route via VPN.
// Fills out_proc_name with the resolved process name.
// Returns 1 (route via VPN tunnel) or 0 (direct connection / bypass).
int alya_vpn_check_peer_route(int proxy_local_port, int peer_remote_port, char *out_proc_name, int max_len);

// Directly checks if a process name matches configured routing rules.
int alya_vpn_should_route(const char *proc_name);

// Checks if a destination host/port matches configured routing rules or requires VPN (e.g. DNS).
// Returns 1 (route via VPN), 0 (bypass VPN / direct), or -1 (no host rule, use process routing).
int alya_vpn_should_route_host(const char *host, int port);
int alya_vpn_infer_process_from_host(const char *host, char *out_proc_name, int max_len);
void alya_vpn_set_tunnel_dns(int enable);
int  alya_vpn_get_tunnel_dns(void);
void alya_vpn_dns_clear(void);
void alya_vpn_add_dns_server(const char *server);
void alya_vpn_add_dns_resolver(const char *resolver);

// LAN Bypass configuration (192.168.x, 10.x, 172.16-31.x, .local)
void alya_vpn_set_bypass_lan(int enable);
int  alya_vpn_get_bypass_lan(void);

// Domain routing rules (*.example.com, etc.)
void alya_vpn_domain_clear(void);
void alya_vpn_add_routing_domain(const char *domain);

// Socket timeouts & low-latency TCP_NODELAY optimization
void alya_vpn_set_timeouts(int handshake_ms, int connect_ms);
void alya_vpn_set_tcp_nodelay(int enable);
int  alya_vpn_get_tcp_nodelay(void);
void alya_vpn_set_server_log_connections(int enable);
int  alya_vpn_get_server_log_connections(void);

// Cross-platform custom TCP listen (supports specific bind IP: 127.0.0.1, 0.0.0.0, etc.)
int  alya_vpn_tcp_listen(const char *bind_addr, int port, int backlog);

// Forward protocol mode: 1 = TCP only, 2 = UDP only, 3 = both (default).
// Controls which forwarded payload types are allowed; the tunnel itself
// always runs over TCP. UDP is carried as UDP-over-TCP datagrams.
void alya_vpn_set_forward_protocol(int mode);
int  alya_vpn_get_forward_protocol(void);

// Client UDP relay (SOCKS5 UDP ASSOCIATE endpoint). Binds a UDP socket
// (fixed port, ephemeral fallback) and returns the bound port, or -1.
// The handshake reports this port in UDP ASSOCIATE replies.
int  alya_vpn_udp_relay_init(const char *bind_addr, int port);
int  alya_vpn_udp_relay_port(void);
// Relay -> tunnel (+ direct bypass) pump. Returns 1 on activity, 0 when idle.
int64_t alya_vpn_pump_client_udp_out(int vpn_sock);
// Tears down associations, mappings and the relay socket.
void alya_vpn_udp_clear(void);
// Marks associations unsynced so ASSOC_REQ is re-sent after a reconnect.
void alya_vpn_udp_resync(void);

// Server per-client UDP association tables (thread-local, like TCP channels).
void alya_vpn_srv_udp_clear(void);
void alya_vpn_srv_udp_close_all(void);

// Server SSRF Protection (Block LAN / Loopback destinations)
void alya_vpn_set_server_block_lan(int enable);
int  alya_vpn_get_server_block_lan(void);

// Server Blocked Ports (e.g. SMTP 25, 465, 587 anti-spam)
void alya_vpn_server_clear_blocked_ports(void);
void alya_vpn_server_add_blocked_port(int port);
int  alya_vpn_server_is_port_blocked(int port);

// Server Max Clients & Atomic Active Client Tracking
void alya_vpn_srv_set_max_clients(int max_clients);
int  alya_vpn_srv_get_max_clients(void);
int  alya_vpn_srv_get_active_clients(void);
int  alya_vpn_srv_client_connected(void);
void alya_vpn_srv_client_disconnected(void);

// Client Custom LAN Ranges & Domains
void alya_vpn_clear_custom_lan(void);
void alya_vpn_add_custom_lan(const char *range_or_domain);

// Channel Idle Timeout & Keep-Alive Ping
void alya_vpn_set_idle_timeout_sec(int sec);
int  alya_vpn_get_idle_timeout_sec(void);
void alya_vpn_set_ping_interval_sec(int sec);
int  alya_vpn_get_ping_interval_sec(void);
int  alya_vpn_send_ping(int sock, int ch_id);

// Traffic Metrics & Performance Statistics
const char *alya_vpn_stats_get_summary(void);
void alya_vpn_stats_reset(void);
uint32_t alya_vpn_get_time_ms(void);

// Cross-platform idle sleep (ms). Use in event loops when no activity detected.
void alya_vpn_sleep_ms(int ms);

// ============================================================================
// Native Channel & Direct Connection Tables (O(1) lookup, 0 heap allocations)
// ============================================================================

// Client Channel Table: channel_id -> app_sock
void alya_vpn_ch_set(int channel_id, int app_sock);
int  alya_vpn_ch_get(int channel_id);
void alya_vpn_ch_remove(int channel_id);
int  alya_vpn_ch_count(void);
int  alya_vpn_ch_id_at(int index);
int  alya_vpn_ch_sock_at(int index);
void alya_vpn_ch_clear(void);

// Client Direct Connection Table: app_sock -> dest_sock
void alya_vpn_direct_set(int app_sock, int dest_sock);
void alya_vpn_direct_set_connecting(int app_sock, int dest_sock, int connecting);
int  alya_vpn_direct_get(int app_sock);
void alya_vpn_direct_remove(int app_sock);
int  alya_vpn_direct_count(void);
int  alya_vpn_direct_app_at(int index);
int  alya_vpn_direct_dest_at(int index);
void alya_vpn_direct_clear(void);
int  alya_vpn_open_direct(int app_sock, const char *host, int port);

// High-speed native direct pump: forwards raw binary bytes bidirectionally
// between all active (app_sock <-> dest_sock) direct connections with zero
// heap allocation and zero hex encoding. Returns 1 if any bytes were transferred, 0 if idle.
int alya_vpn_pump_direct(void);



// Server Channel Table: channel_id -> dest_sock
void alya_vpn_srv_ch_set(int channel_id, int dest_sock);
int  alya_vpn_srv_ch_get(int channel_id);
void alya_vpn_srv_ch_remove(int channel_id);
int  alya_vpn_srv_ch_count(void);
int  alya_vpn_srv_ch_id_at(int index);
int  alya_vpn_srv_ch_sock_at(int index);
void alya_vpn_srv_ch_clear(void);
void alya_vpn_srv_close_all(void);

// ============================================================================
// Native High-Speed VPN Tunnel Pumps (Zero Alya Heap Allocations, Zero Hex)
// ============================================================================

// Opens a client VPN channel: marks app_sock nonblocking, associates with channel_id,
// and transmits AV02 MSG_CONNECT_REQ to vpn_sock. Returns 0 on success, -1 on send error.
int alya_vpn_open_client_channel(int vpn_sock, int channel_id, const char *host, int port, int app_sock);

// High-speed native client tunnel pump:
// Reads AV02 binary frames from vpn_sock and forwards raw payload directly to app sockets;
// Reads raw application bytes from active channels, encrypts into AV02 frames, and forwards to vpn_sock.
// Returns 1 if activity, 0 if idle, -1 if vpn_sock closed/error.
int64_t alya_vpn_pump_client_vpn(int vpn_sock);

// High-speed native server tunnel pump:
// Reads AV02 binary frames from client_sock, handles CONNECT_REQ / DATA / CLOSE / PING;
// Reads raw destination bytes from active server channels, encrypts into AV02 frames, forwards to client_sock.
// Returns 1 if activity, 0 if idle, -1 if client_sock closed/error.
int64_t alya_vpn_pump_server_vpn(int client_sock);

// Automatically configures or restores the OS system proxy (127.0.0.1:port)
void alya_vpn_set_system_proxy(int enable, int port);

// Hooks OS console events (Ctrl+C, close) to cleanly disable system proxy on exit
void alya_vpn_init_system_proxy_hook(void);
int alya_vpn_is_stop_requested(void);
void alya_vpn_request_stop(void);



// ============================================================================
// Buffer Pool & Zero-Copy I/O (New - eliminates hex encoding/decoding)
// ============================================================================

#include "buffer_pool.h"
// All buffer pool functions are declared in buffer_pool.h:
// - alya_vpn_buffer_pool_init / shutdown
// - alya_vpn_buffer_acquire / release / ref
// - alya_vpn_buffer_data / used / set_used / reset / capacity
// - alya_vpn_sock_recv_into_buffer / sock_send_from_buffer
// - alya_vpn_sock_send_frame / sock_recv_frame (scatter/gather)
// - alya_vpn_pack_frame_into_buffer / unpack_frame_from_buffer
// - alya_vpn_unpack_frame_buffer_type
// - alya_vpn_buffer_pool_stats / get_stats

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_PROC_RESOLVER_H