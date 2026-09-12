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

#ifdef __cplusplus
}
#endif

#endif // ALYA_VPN_PROC_RESOLVER_H
