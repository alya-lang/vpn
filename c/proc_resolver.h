#ifndef ALYA_VPN_PROC_RESOLVER_H
#define ALYA_VPN_PROC_RESOLVER_H

#ifdef __cplusplus
extern "C" {
#endif

// Resolves the executable filename (e.g. "Discord.exe" or "discord")
// of the process that owns the specified local TCP port.
// Writes the filename to out_name (up to max_len bytes).
// Returns 1 on success, 0 on failure / process not found.
int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len);

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

// Resolves process from local peer port and determines whether it should route via VPN.
// Fills out_proc_name with the resolved process name.
// Returns 1 (route via VPN tunnel) or 0 (direct connection / bypass).
int alya_vpn_check_peer_route(int peer_port, char *out_proc_name, int max_len);

// Directly checks if a process name matches configured routing rules.
int alya_vpn_should_route(const char *proc_name);

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
int  alya_vpn_direct_get(int app_sock);
void alya_vpn_direct_remove(int app_sock);
int  alya_vpn_direct_count(void);
int  alya_vpn_direct_app_at(int index);
int  alya_vpn_direct_dest_at(int index);
void alya_vpn_direct_clear(void);

// Server Channel Table: channel_id -> dest_sock
void alya_vpn_srv_ch_set(int channel_id, int dest_sock);
int  alya_vpn_srv_ch_get(int channel_id);
void alya_vpn_srv_ch_remove(int channel_id);
int  alya_vpn_srv_ch_count(void);
int  alya_vpn_srv_ch_id_at(int index);
int  alya_vpn_srv_ch_sock_at(int index);
void alya_vpn_srv_ch_clear(void);

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_PROC_RESOLVER_H
