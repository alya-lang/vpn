#include "proc_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

    DWORD size = 0;
    // Query buffer size
    pGetTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    ALYA_MIB_TCPTABLE_OWNER_PID *table = (ALYA_MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!table) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    int found = 0;
    if (pGetTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
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

int alya_vpn_sock_recv_hex(int sock, char *out_hex, int max_bytes) {
    if (!out_hex || max_bytes <= 0) return 0;
    unsigned char buf[8192];
    int to_read = max_bytes > (int)sizeof(buf) ? (int)sizeof(buf) : max_bytes;
    int n = recv((SOCKET)sock, (char *)buf, to_read, 0);
    if (n <= 0) {
        out_hex[0] = '\0';
        return n;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        out_hex[i * 2] = hex_chars[(buf[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[buf[i] & 0x0F];
    }
    out_hex[n * 2] = '\0';
    return n;
}

int alya_vpn_sock_send_hex(int sock, const char *hex_str, int hex_len) {
    if (!hex_str || hex_len <= 0 || hex_len % 2 != 0) return 0;
    int byte_len = hex_len / 2;
    unsigned char buf[8192];
    if (byte_len > (int)sizeof(buf)) byte_len = (int)sizeof(buf);

    for (int i = 0; i < byte_len; ++i) {
        int hi = hex_str[i * 2];
        int lo = hex_str[i * 2 + 1];
        int v_hi = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
        int v_lo = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
        buf[i] = (unsigned char)((v_hi << 4) | v_lo);
    }
    return send((SOCKET)sock, (const char *)buf, byte_len, 0);
}

