#include "proc_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#if defined(_MSC_VER)
#define ALYA_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define ALYA_THREAD_LOCAL _Thread_local
#else
#define ALYA_THREAD_LOCAL __thread
#endif

#if defined(__GNUC__) || defined(__clang__)
static void __attribute__((constructor)) init_unbuffered_io(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}
#endif

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

// Dynamic typedefs for IpHlpApi functions to avoid hard compile-time library linkage
typedef DWORD (WINAPI *pfnGetExtendedTcpTable)(
    PVOID pTcpTable,
    PDWORD pdwSize,
    BOOL bOrder,
    ULONG ulAf,
    ULONG TableClass,
    ULONG Reserved
);

typedef DWORD (WINAPI *pfnGetExtendedUdpTable)(
    PVOID pUdpTable,
    PDWORD pdwSize,
    BOOL bOrder,
    ULONG ulAf,
    ULONG TableClass,
    ULONG Reserved
);

#define TCP_TABLE_OWNER_PID_ALL 5
#define UDP_TABLE_OWNER_PID 1

// Internal structure matching MIB_TCPROW_OWNER_PID
typedef struct {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} ALYA_MIB_TCPROW_OWNER_PID;

typedef struct {
    DWORD dwNumEntries;
    ALYA_MIB_TCPROW_OWNER_PID table[1];
} ALYA_MIB_TCPTABLE_OWNER_PID;

typedef struct {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwOwningPid;
} ALYA_MIB_UDPROW_OWNER_PID;

typedef struct {
    DWORD dwNumEntries;
    ALYA_MIB_UDPROW_OWNER_PID table[1];
} ALYA_MIB_UDPTABLE_OWNER_PID;

// Internal structure matching MIB_TCP6ROW_OWNER_PID (IPv6)
typedef struct {
    UCHAR  ucLocalAddr[16];
    DWORD  dwLocalScopeId;
    DWORD  dwLocalPort;
    UCHAR  ucRemoteAddr[16];
    DWORD  dwRemoteScopeId;
    DWORD  dwRemotePort;
    DWORD  dwState;
    DWORD  dwOwningPid;
} ALYA_MIB_TCP6ROW_OWNER_PID;

typedef struct {
    DWORD dwNumEntries;
    ALYA_MIB_TCP6ROW_OWNER_PID table[1];
} ALYA_MIB_TCP6TABLE_OWNER_PID;

static void extract_basename(const char *full_path, char *out_name, int max_len) {
    if (!full_path || !out_name || max_len <= 0) return;
    const char *slash = strrchr(full_path, '\\');
    const char *fslash = strrchr(full_path, '/');
    const char *base = full_path;
    if (slash && slash >= base) base = slash + 1;
    if (fslash && fslash >= base) base = fslash + 1;

    strncpy(out_name, base, (size_t)max_len - 1);
    out_name[max_len - 1] = '\0';
}

static int get_process_name_by_pid(DWORD pid, char *out_name, int max_len) {
    if (pid == 0) {
        strncpy(out_name, "System", (size_t)max_len - 1);
        out_name[max_len - 1] = '\0';
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }
    if (!hProc) return 0;

    char path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    typedef BOOL (WINAPI *pfnQueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    pfnQueryFullProcessImageNameA pQuery = hKernel ? (pfnQueryFullProcessImageNameA)GetProcAddress(hKernel, "QueryFullProcessImageNameA") : NULL;

    int success = 0;
    if (pQuery && pQuery(hProc, 0, path, &size)) {
        extract_basename(path, out_name, max_len);
        success = 1;
    }
    CloseHandle(hProc);
    return success;
}

int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;

    HMODULE hIpHlp = LoadLibraryA("iphlpapi.dll");
    if (!hIpHlp) return 0;

    pfnGetExtendedTcpTable pGetTable = (pfnGetExtendedTcpTable)GetProcAddress(hIpHlp, "GetExtendedTcpTable");
    if (!pGetTable) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    uint16_t target_port_network = htons((uint16_t)local_port);
    int found = 0;

    // --- IPv4 lookup ---
    DWORD size = 0;
    pGetTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size > 0) {
        ALYA_MIB_TCPTABLE_OWNER_PID *table = (ALYA_MIB_TCPTABLE_OWNER_PID *)malloc(size);
        if (table) {
            if (pGetTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    if (table->table[i].dwLocalPort == target_port_network) {
                        DWORD pid = table->table[i].dwOwningPid;
                        found = get_process_name_by_pid(pid, out_name, max_len);
                        break;
                    }
                }
            }
            free(table);
        }
    }

    // --- IPv6 fallback (curl connects via IPv6 when DNS returns AAAA records) ---
    if (!found) {
        DWORD size6 = 0;
        pGetTable(NULL, &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size6 > 0) {
            ALYA_MIB_TCP6TABLE_OWNER_PID *table6 = (ALYA_MIB_TCP6TABLE_OWNER_PID *)malloc(size6);
            if (table6) {
                if (pGetTable(table6, &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
                        if (table6->table[i].dwLocalPort == target_port_network) {
                            DWORD pid = table6->table[i].dwOwningPid;
                            found = get_process_name_by_pid(pid, out_name, max_len);
                            break;
                        }
                    }
                }
                free(table6);
            }
        }
    }

    FreeLibrary(hIpHlp);
    return found;
}


int alya_vpn_get_udp_process_by_port(int local_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;

    HMODULE hIpHlp = LoadLibraryA("iphlpapi.dll");
    if (!hIpHlp) return 0;

    pfnGetExtendedUdpTable pGetTable = (pfnGetExtendedUdpTable)GetProcAddress(hIpHlp, "GetExtendedUdpTable");
    if (!pGetTable) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    DWORD size = 0;
    pGetTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    ALYA_MIB_UDPTABLE_OWNER_PID *table = (ALYA_MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!table) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    int found = 0;
    if (pGetTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        uint16_t target_port_network = htons((uint16_t)local_port);
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            if (table->table[i].dwLocalPort == target_port_network) {
                DWORD pid = table->table[i].dwOwningPid;
                found = get_process_name_by_pid(pid, out_name, max_len);
                break;
            }
        }
    }

    free(table);
    FreeLibrary(hIpHlp);
    return found;
}

#elif defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef SOCKET
#define SOCKET int
#endif

static int get_socket_inode(const char *net_file, int local_port) {
    FILE *f = fopen(net_file, "r");
    if (!f) return -1;

    char line[512];
    // Skip header
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    int target_inode = -1;
    while (fgets(line, sizeof(line), f)) {
        int sl;
        unsigned int local_ip, local_p;
        int inode;
        if (sscanf(line, "%d: %x:%x %*x:%*x %*x %*x:%*x %*x:%*x %*x %*d %*d %d",
                   &sl, &local_ip, &local_p, &inode) >= 3) {
            if ((int)local_p == local_port) {
                target_inode = inode;
                break;
            }
        }
    }
    fclose(f);
    return target_inode;
}

int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len) {
    int inode = get_socket_inode("/proc/net/tcp", local_port);
    if (inode <= 0) {
        inode = get_socket_inode("/proc/net/tcp6", local_port);
    }
    if (inode <= 0) return 0;

    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    struct dirent *entry;
    char target_socket[64];
    snprintf(target_socket, sizeof(target_socket), "socket:[%d]", inode);

    int found = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        char fd_dir_path[256];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%s/fd", entry->d_name);
        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            char link_path[512];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir_path, fd_entry->d_name);
            char target[256] = {0};
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len > 0 && strcmp(target, target_socket) == 0) {
                // Found PID! Read /proc/<pid>/comm
                char comm_path[256];
                snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                FILE *comm_f = fopen(comm_path, "r");
                if (comm_f) {
                    if (fgets(out_name, max_len, comm_f)) {
                        char *nl = strchr(out_name, '\n');
                        if (nl) *nl = '\0';
                        found = 1;
                    }
                    fclose(comm_f);
                }
                break;
            }
        }
        closedir(fd_dir);
        if (found) break;
    }

    closedir(dir);
    return found;
}

int alya_vpn_get_udp_process_by_port(int local_port, char *out_name, int max_len) {
    return alya_vpn_get_process_by_port(local_port, out_name, max_len);
}

#else

int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len) {
    (void)local_port;
    (void)out_name;
    (void)max_len;
    return 0; // Unsupported platform
}

int alya_vpn_get_udp_process_by_port(int local_port, char *out_name, int max_len) {
    (void)local_port;
    (void)out_name;
    (void)max_len;
    return 0;
}

#endif

int alya_vpn_socks5_handshake(int client_sock, char *out_host, int max_host_len) {
    if (!out_host || max_host_len < 16) return -1;

#if defined(_WIN32)
    DWORD tv = 3000;
    setsockopt((SOCKET)client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt((SOCKET)client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt((SOCKET)client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt((SOCKET)client_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif

    // 1. SOCKS5 Greeting: [0x05, NMETHODS, METHODS...]
    unsigned char greet[256];
    int n = recv((SOCKET)client_sock, (char *)greet, sizeof(greet), 0);
    if (n < 2 || greet[0] != 0x05) {
        return -1;
    }

    // Respond: [0x05, 0x00] (No auth required)
    const unsigned char greet_resp[2] = {0x05, 0x00};
    if (send((SOCKET)client_sock, (const char *)greet_resp, 2, 0) != 2) {
        return -1;
    }

    // 2. SOCKS5 Request: [0x05, CMD(1), RSV(0), ATYP(1), DST.ADDR, DST.PORT(2)]
    unsigned char req[512];
    n = recv((SOCKET)client_sock, (char *)req, sizeof(req), 0);
    if (n < 7 || req[0] != 0x05 || req[1] != 0x01) {
        const unsigned char fail_resp[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send((SOCKET)client_sock, (const char *)fail_resp, 10, 0);
        return -1;
    }

    int atyp = req[3];
    int target_port = 0;

    if (atyp == 1) { // IPv4 (4 bytes)
        if (n < 10) return -1;
        snprintf(out_host, (size_t)max_host_len, "%u.%u.%u.%u", req[4], req[5], req[6], req[7]);
        target_port = (req[8] << 8) | req[9];
    } else if (atyp == 3) { // Domain name (1 byte length + string)
        int domain_len = req[4];
        if (n < 5 + domain_len + 2 || domain_len >= max_host_len) return -1;
        memcpy(out_host, &req[5], (size_t)domain_len);
        out_host[domain_len] = '\0';
        target_port = (req[5 + domain_len] << 8) | req[5 + domain_len + 1];
    } else if (atyp == 4) { // IPv6 (16 bytes)
        if (n < 22) return -1;
        inet_ntop(AF_INET6, &req[4], out_host, (socklen_t)max_host_len);
        target_port = (req[20] << 8) | req[21];
    } else {
        const unsigned char fail_resp[10] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send((SOCKET)client_sock, (const char *)fail_resp, 10, 0);
        return -1;
    }

    // Respond success: [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x10, 0x00]
    const unsigned char ok_resp[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x10, 0x00};
    send((SOCKET)client_sock, (const char *)ok_resp, 10, 0);

    return target_port;
}

static char s_recv_hex_buf[65536];

const char *alya_vpn_sock_recv_hex(int sock, int max_bytes) {
    if (max_bytes <= 0 || max_bytes > 32768) max_bytes = 8192;
    unsigned char buf[8192];
    int to_read = max_bytes > (int)sizeof(buf) ? (int)sizeof(buf) : max_bytes;
    int n = recv((SOCKET)sock, (char *)buf, to_read, 0);
    if (n <= 0) {
        return "";
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        s_recv_hex_buf[i * 2] = hex_chars[(buf[i] >> 4) & 0x0F];
        s_recv_hex_buf[i * 2 + 1] = hex_chars[buf[i] & 0x0F];
    }
    s_recv_hex_buf[n * 2] = '\0';
    return s_recv_hex_buf;
}


#ifndef SOCKET
#define SOCKET int
#endif

int alya_vpn_sock_send_hex(int sock, const char *hex_str, int hex_len) {
    if (!hex_str || hex_len <= 0 || hex_len % 2 != 0) return 0;
    int total_bytes = hex_len / 2;
    int total_sent = 0;
    unsigned char buf[8192];
    int offset = 0;
    while (offset < total_bytes) {
        int chunk_bytes = total_bytes - offset;
        if (chunk_bytes > (int)sizeof(buf)) chunk_bytes = (int)sizeof(buf);
        for (int i = 0; i < chunk_bytes; ++i) {
            int hi = hex_str[(offset + i) * 2];
            int lo = hex_str[(offset + i) * 2 + 1];
            int v_hi = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
            int v_lo = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
            buf[i] = (unsigned char)((v_hi << 4) | v_lo);
        }
        int s = send((SOCKET)sock, (const char *)buf, chunk_bytes, 0);
        if (s <= 0) return s;
        total_sent += s;
        offset += chunk_bytes;
    }
    return total_sent;
}

// ============================================================================
// Split-Tunneling Routing Engine (Native C, immune to cyclic buffer wrap)
// ============================================================================

#if defined(_WIN32)
#define ALYA_STRICMP _stricmp
#define ALYA_STRNICMP _strnicmp
#else
#include <strings.h>
#define ALYA_STRICMP strcasecmp
#define ALYA_STRNICMP strncasecmp
#endif

static int s_split_mode = 0; // 0 = all, 1 = include, 2 = exclude
static char s_split_apps[128][64];
static int s_split_app_count = 0;

static int pattern_match_c(const char *pattern, const char *text) {
    if (!pattern || !text || !pattern[0] || !text[0]) return 0;

    // Case-insensitive exact match
    if (ALYA_STRICMP(pattern, text) == 0) return 1;

    // .exe suffix tolerance (e.g. "discord" matches "discord.exe" or vice versa)
    char buf[128];
    snprintf(buf, sizeof(buf), "%s.exe", pattern);
    if (ALYA_STRICMP(buf, text) == 0) return 1;
    snprintf(buf, sizeof(buf), "%s.exe", text);
    if (ALYA_STRICMP(pattern, buf) == 0) return 1;

    // Wildcard match: *substring*, *suffix, prefix*
    size_t plen = strlen(pattern);
    size_t tlen = strlen(text);
    if (plen >= 2 && pattern[0] == '*' && pattern[plen - 1] == '*') {
        char inner[128];
        size_t ilen = plen - 2;
        if (ilen >= sizeof(inner)) return 0;
        memcpy(inner, pattern + 1, ilen);
        inner[ilen] = '\0';
        char p_lower[128], t_lower[128];
        for (size_t i = 0; i <= ilen; ++i) p_lower[i] = (char)tolower((unsigned char)inner[i]);
        if (tlen >= sizeof(t_lower)) return 0;
        for (size_t i = 0; i <= tlen; ++i) t_lower[i] = (char)tolower((unsigned char)text[i]);
        return strstr(t_lower, p_lower) != NULL;
    }
    if (pattern[0] == '*' && plen > 1) {
        const char *suffix = pattern + 1;
        size_t slen = strlen(suffix);
        if (tlen >= slen && ALYA_STRICMP(text + (tlen - slen), suffix) == 0) return 1;
    }
    if (plen > 1 && pattern[plen - 1] == '*') {
        char prefix[128];
        size_t prlen = plen - 1;
        if (prlen >= sizeof(prefix)) return 0;
        memcpy(prefix, pattern, prlen);
        prefix[prlen] = '\0';
        if (tlen >= prlen && ALYA_STRNICMP(prefix, text, prlen) == 0) return 1;
    }

    return 0;
}

void alya_vpn_sleep_ms(int ms) {
    if (ms <= 0) return;
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000);
#endif
}

void alya_vpn_set_routing(int mode, const char *apps_csv) {
    s_split_mode = mode;
    s_split_app_count = 0;
    if (!apps_csv || !apps_csv[0]) return;

    const char *start = apps_csv;
    while (*start && s_split_app_count < 128) {
        while (*start == ' ' || *start == ',' || *start == '\t' || *start == '\r' || *start == '\n') start++;
        if (!*start) break;
        const char *end = start;
        while (*end && *end != ',' && *end != '\r' && *end != '\n') end++;
        size_t len = (size_t)(end - start);
        while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t')) len--;
        if (len > 0 && len < 64) {
            memcpy(s_split_apps[s_split_app_count], start, len);
            s_split_apps[s_split_app_count][len] = '\0';
            s_split_app_count++;
        }
        start = end;
    }
}

// Adds a single app name to the routing list (avoids Alya string concat bug
// where array elements are converted to their pointer address in decimal).
void alya_vpn_add_routing_app(const char *app_name) {
    if (!app_name || !app_name[0] || s_split_app_count >= 128) return;
    size_t len = strlen(app_name);
    if (len == 0 || len >= 64) return;
    strncpy(s_split_apps[s_split_app_count], app_name, 63);
    s_split_apps[s_split_app_count][63] = '\0';
    s_split_app_count++;
}

int alya_vpn_should_route(const char *proc_name) {
    if (s_split_mode == 0) return 1; // route all

    // Unknown process: privacy-safe default — route through VPN in whitelist mode,
    // bypass VPN in blacklist mode (blacklist means "exclude these specific apps").
    int is_unknown = (!proc_name || !proc_name[0] || strcmp(proc_name, "unknown") == 0);
    if (is_unknown) {
        return (s_split_mode == 2) ? 0 : 1;
    }

    int matched = 0;
    for (int i = 0; i < s_split_app_count; ++i) {
        if (pattern_match_c(s_split_apps[i], proc_name)) {
            matched = 1;
            break;
        }
    }
    if (s_split_mode == 1) return matched ? 1 : 0; // Whitelist
    if (s_split_mode == 2) return matched ? 0 : 1; // Blacklist
    return 1;
}

int alya_vpn_check_peer_route(int peer_port, char *out_proc_name, int max_len) {
    if (!out_proc_name || max_len <= 0) return 1;
    out_proc_name[0] = '\0';
    int res = alya_vpn_get_process_by_port(peer_port, out_proc_name, max_len);
    if (!res || !out_proc_name[0]) {
        strncpy(out_proc_name, "unknown", (size_t)max_len - 1);
        out_proc_name[max_len - 1] = '\0';
    }
    return alya_vpn_should_route(out_proc_name);
}



// ============================================================================
// Native Channel & Direct Connection Tables (O(1) lookup, 0 heap allocations)
// ============================================================================

#define ALYA_MAX_CHANNELS 2048

typedef struct {
    int in_use;
    int channel_id;
    int app_sock;
} AlyaChannelEntry;

typedef struct {
    int in_use;
    int app_sock;
    int dest_sock;
} AlyaDirectEntry;

typedef struct {
    int in_use;
    int channel_id;
    int dest_sock;
} AlyaSrvChannelEntry;

static AlyaChannelEntry s_client_channels[ALYA_MAX_CHANNELS];
static AlyaDirectEntry s_client_directs[ALYA_MAX_CHANNELS];
static ALYA_THREAD_LOCAL AlyaSrvChannelEntry s_server_channels[ALYA_MAX_CHANNELS];

// Client Channel Table
void alya_vpn_ch_set(int channel_id, int app_sock) {
    int free_slot = -1;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use && s_client_channels[i].channel_id == channel_id) {
            s_client_channels[i].app_sock = app_sock;
            return;
        }
        if (!s_client_channels[i].in_use && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot >= 0) {
        s_client_channels[free_slot].in_use = 1;
        s_client_channels[free_slot].channel_id = channel_id;
        s_client_channels[free_slot].app_sock = app_sock;
    }
}

int alya_vpn_ch_get(int channel_id) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use && s_client_channels[i].channel_id == channel_id) {
            return s_client_channels[i].app_sock;
        }
    }
    return -1;
}

void alya_vpn_ch_remove(int channel_id) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use && s_client_channels[i].channel_id == channel_id) {
            s_client_channels[i].in_use = 0;
            s_client_channels[i].channel_id = 0;
            s_client_channels[i].app_sock = -1;
            return;
        }
    }
}

int alya_vpn_ch_count(void) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use) count++;
    }
    return count;
}

int alya_vpn_ch_id_at(int index) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use) {
            if (count == index) return s_client_channels[i].channel_id;
            count++;
        }
    }
    return 0;
}

int alya_vpn_ch_sock_at(int index) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use) {
            if (count == index) return s_client_channels[i].app_sock;
            count++;
        }
    }
    return -1;
}

void alya_vpn_ch_clear(void) {
    memset(s_client_channels, 0, sizeof(s_client_channels));
}

// Client Direct Connections
void alya_vpn_direct_set(int app_sock, int dest_sock) {
    int free_slot = -1;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use && s_client_directs[i].app_sock == app_sock) {
            s_client_directs[i].dest_sock = dest_sock;
            return;
        }
        if (!s_client_directs[i].in_use && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        s_client_directs[free_slot].in_use = 1;
        s_client_directs[free_slot].app_sock = app_sock;
        s_client_directs[free_slot].dest_sock = dest_sock;
    }
}

int alya_vpn_direct_get(int app_sock) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use && s_client_directs[i].app_sock == app_sock) {
            return s_client_directs[i].dest_sock;
        }
    }
    return -1;
}

void alya_vpn_direct_remove(int app_sock) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use && s_client_directs[i].app_sock == app_sock) {
            s_client_directs[i].in_use = 0;
            s_client_directs[i].app_sock = -1;
            s_client_directs[i].dest_sock = -1;
            return;
        }
    }
}

int alya_vpn_direct_count(void) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use) count++;
    }
    return count;
}

int alya_vpn_direct_app_at(int index) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use) {
            if (count == index) return s_client_directs[i].app_sock;
            count++;
        }
    }
    return -1;
}

int alya_vpn_direct_dest_at(int index) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use) {
            if (count == index) return s_client_directs[i].dest_sock;
            count++;
        }
    }
    return -1;
}

void alya_vpn_direct_clear(void) {
    memset(s_client_directs, 0, sizeof(s_client_directs));
}

// Server Channel Table
void alya_vpn_srv_ch_set(int channel_id, int dest_sock) {
    int free_slot = -1;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use && s_server_channels[i].channel_id == channel_id) {
            s_server_channels[i].dest_sock = dest_sock;
            return;
        }
        if (!s_server_channels[i].in_use && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        s_server_channels[free_slot].in_use = 1;
        s_server_channels[free_slot].channel_id = channel_id;
        s_server_channels[free_slot].dest_sock = dest_sock;
    }
}

int alya_vpn_srv_ch_get(int channel_id) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use && s_server_channels[i].channel_id == channel_id) {
            return s_server_channels[i].dest_sock;
        }
    }
    return -1;
}

void alya_vpn_srv_ch_remove(int channel_id) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use && s_server_channels[i].channel_id == channel_id) {
            s_server_channels[i].in_use = 0;
            s_server_channels[i].channel_id = 0;
            s_server_channels[i].dest_sock = -1;
            return;
        }
    }
}

int alya_vpn_srv_ch_count(void) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use) count++;
    }
    return count;
}

int alya_vpn_srv_ch_id_at(int index) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use) {
            if (count == index) return s_server_channels[i].channel_id;
            count++;
        }
    }
    return 0;
}

int alya_vpn_srv_ch_sock_at(int index) {
    int count = 0;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use) {
            if (count == index) return s_server_channels[i].dest_sock;
            count++;
        }
    }
    return -1;
}

void alya_vpn_srv_ch_clear(void) {
    memset(s_server_channels, 0, sizeof(s_server_channels));
}


