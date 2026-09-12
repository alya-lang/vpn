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

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_PROC_RESOLVER_H
