#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#include "proc_resolver.h"
#include "buffer_pool.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#if !defined(_WIN32)
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#ifndef SOCKET
#define SOCKET int
#endif
#endif


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
#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif
}
#endif


#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>

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
    int success = 0;
    if (hProc) {
        char path[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        typedef BOOL (WINAPI *pfnQueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
        HMODULE hKernel = GetModuleHandleA("kernel32.dll");
        pfnQueryFullProcessImageNameA pQuery = hKernel ? (pfnQueryFullProcessImageNameA)GetProcAddress(hKernel, "QueryFullProcessImageNameA") : NULL;

        if (pQuery && pQuery(hProc, 0, path, &size)) {
            extract_basename(path, out_name, max_len);
            success = 1;
        }
        CloseHandle(hProc);
    }

    // Fallback: Toolhelp32 snapshot works even without PROCESS_QUERY rights
    if (!success) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        extract_basename(pe.szExeFile, out_name, max_len);
                        success = 1;
                        break;
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

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

// NEW FUNCTION: Resolves process by matching BOTH proxy local port AND peer remote port.
// This is needed because the VPN proxy accepts connections on proxy_local_port,
// and each client connection has a unique peer_remote_port (ephemeral port).
// The TCP table entry for the accepted connection will have:
//   dwLocalPort == proxy_local_port (in network order)
//   dwRemotePort == peer_remote_port (in network order)
int alya_vpn_get_process_by_peer_port(int proxy_local_port, int peer_remote_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;

    HMODULE hIpHlp = LoadLibraryA("iphlpapi.dll");
    if (!hIpHlp) return 0;

    pfnGetExtendedTcpTable pGetTable = (pfnGetExtendedTcpTable)GetProcAddress(hIpHlp, "GetExtendedTcpTable");
    if (!pGetTable) {
        FreeLibrary(hIpHlp);
        return 0;
    }

    uint16_t target_local_port_network = htons((uint16_t)proxy_local_port);
    uint16_t target_remote_port_network = htons((uint16_t)peer_remote_port);
    int found = 0;

    // --- IPv4 lookup ---
    // Note: From the client app's perspective (e.g. Chrome/curl connecting to proxy):
    // client_socket.dwLocalPort == peer_remote_port (ephemeral port)
    // client_socket.dwRemotePort == proxy_local_port (e.g. 1080)
    DWORD size = 0;
    pGetTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size > 0) {
        ALYA_MIB_TCPTABLE_OWNER_PID *table = (ALYA_MIB_TCPTABLE_OWNER_PID *)malloc(size);
        if (table) {
            if (pGetTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                // Pass 1: Match both client local port (peer_remote_port) and remote port (proxy_local_port)
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    if (table->table[i].dwLocalPort == target_remote_port_network &&
                        table->table[i].dwRemotePort == target_local_port_network) {
                        DWORD pid = table->table[i].dwOwningPid;
                        found = get_process_name_by_pid(pid, out_name, max_len);
                        break;
                    }
                }
                // Pass 2: Fallback to matching just client local port if not found
                if (!found) {
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        if (table->table[i].dwLocalPort == target_remote_port_network) {
                            DWORD pid = table->table[i].dwOwningPid;
                            found = get_process_name_by_pid(pid, out_name, max_len);
                            break;
                        }
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
                        if (table6->table[i].dwLocalPort == target_remote_port_network &&
                            table6->table[i].dwRemotePort == target_local_port_network) {
                            DWORD pid = table6->table[i].dwOwningPid;
                            found = get_process_name_by_pid(pid, out_name, max_len);
                            break;
                        }
                    }
                    if (!found) {
                        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
                            if (table6->table[i].dwLocalPort == target_remote_port_network) {
                                DWORD pid = table6->table[i].dwOwningPid;
                                found = get_process_name_by_pid(pid, out_name, max_len);
                                break;
                            }
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

// Linux equivalent for peer port matching: reads /proc/net/tcp and /proc/net/tcp6
// and matches both local port AND remote port to find the correct inode.
// The inode is then matched against /proc/<pid>/fd/ socket symlinks.
int alya_vpn_get_process_by_peer_port(int proxy_local_port, int peer_remote_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;

    // Scan /proc/net/tcp (IPv4)
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return 0;

    char line[512];
    // Skip header
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        // Try IPv6
        f = fopen("/proc/net/tcp6", "r");
        if (!f) return 0;
        if (!fgets(line, sizeof(line), f)) {
            fclose(f);
            return 0;
        }
    }

    int target_inode = -1;
    while (fgets(line, sizeof(line), f)) {
        int sl;
        unsigned int local_ip, local_p, remote_ip, remote_p;
        int inode;
        // Format: sl local_address:local_port rem_address:rem_port st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
        if (sscanf(line, "%d: %x:%x %x:%x %*x %*x:%*x %*x:%*x %*x %*d %*d %d",
                   &sl, &local_ip, &local_p, &remote_ip, &remote_p, &inode) >= 5) {
            if ((int)local_p == peer_remote_port && (int)remote_p == proxy_local_port) {
                target_inode = inode;
                break;
            }
        }
    }
    fclose(f);

    if (target_inode <= 0) {
        // Try IPv6
        f = fopen("/proc/net/tcp6", "r");
        if (f) {
            if (fgets(line, sizeof(line), f)) {
                while (fgets(line, sizeof(line), f)) {
                    int sl;
                    unsigned int local_ip[4], local_p, remote_ip[4], remote_p;
                    int inode;
                    if (sscanf(line, "%d: %x:%x:%x:%x:%x %x:%x:%x:%x:%x %*x %*x:%*x %*x:%*x %*x %*d %*d %d",
                               &sl,
                               &local_ip[0], &local_ip[1], &local_ip[2], &local_ip[3], &local_p,
                               &remote_ip[0], &remote_ip[1], &remote_ip[2], &remote_ip[3], &remote_p,
                               &inode) >= 10) {
                        if ((int)local_p == peer_remote_port && (int)remote_p == proxy_local_port) {
                            target_inode = inode;
                            break;
                        }
                    }
                }
            }
            fclose(f);
        }
    }


    if (target_inode <= 0) return 0;

    // Now find the process owning this inode (same as alya_vpn_get_process_by_port)
    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    struct dirent *entry;
    char target_socket[64];
    snprintf(target_socket, sizeof(target_socket), "socket:[%d]", target_inode);

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

#elif defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>

static int macos_get_proc_name_or_bundle(pid_t pid, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;
    char path_buf[1024];
    if (proc_pidpath((int)pid, path_buf, sizeof(path_buf)) > 0) {
        char *app_ext = strstr(path_buf, ".app");
        if (app_ext) {
            char *slash = app_ext;
            while (slash > path_buf && *(slash - 1) != '/') slash--;
            size_t bname_len = (size_t)(app_ext - slash);
            if (bname_len > 0 && bname_len < (size_t)max_len) {
                memcpy(out_name, slash, bname_len);
                out_name[bname_len] = '\0';
                return 1;
            }
        }
    }
    char name_buf[256];
    if (proc_name((int)pid, name_buf, sizeof(name_buf)) > 0) {
        strncpy(out_name, name_buf, (size_t)max_len - 1);
        out_name[max_len - 1] = '\0';
        return 1;
    }
    return 0;
}

int alya_vpn_get_process_by_peer_port(int proxy_local_port, int peer_remote_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;
    out_name[0] = '\0';

    int num_pids = proc_listallpids(NULL, 0);
    if (num_pids <= 0) return 0;

    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * (size_t)num_pids * 2);
    if (!pids) return 0;

    num_pids = proc_listallpids(pids, (int)(sizeof(pid_t) * (size_t)num_pids * 2));
    if (num_pids <= 0) {
        free(pids);
        return 0;
    }

    int found = 0;
    pid_t my_pid = getpid();
    for (int i = 0; i < num_pids && !found; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == my_pid) continue;

        int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (buf_size <= 0) continue;

        struct proc_fdinfo stack_fds[128];
        struct proc_fdinfo *fds = stack_fds;
        int count = buf_size / (int)sizeof(struct proc_fdinfo);
        if (count > 128) {
            fds = (struct proc_fdinfo *)malloc((size_t)buf_size);
            if (!fds) continue;
        }

        int num_fds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, buf_size);
        if (num_fds <= 0) {
            if (fds != stack_fds) free(fds);
            continue;
        }

        count = num_fds / (int)sizeof(struct proc_fdinfo);
        for (int j = 0; j < count; ++j) {
            if (fds[j].proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo si;
                memset(&si, 0, sizeof(si));
                int s = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
                if (s > (int)sizeof(struct proc_fileinfo)) {
                    int kind = si.psi.soi_kind;
                    if (kind == SOCKINFO_TCP || kind == SOCKINFO_IN || kind == 0) {
                        int raw_lport = (int)(uint16_t)si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
                        int raw_fport = (int)(uint16_t)si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport;
                        int swap_lport = (int)ntohs((uint16_t)raw_lport);
                        int swap_fport = (int)ntohs((uint16_t)raw_fport);

                        int match_l = (raw_lport == peer_remote_port || swap_lport == peer_remote_port);
                        int match_f = (raw_fport == proxy_local_port || swap_fport == proxy_local_port);
                        if (match_l && match_f) {
                            if (!macos_get_proc_name_or_bundle(pid, out_name, max_len)) {
                                snprintf(out_name, (size_t)max_len, "pid-%d", (int)pid);
                            }
                            found = 1;
                            break;
                        }
                    }
                }
            }
        }
        if (fds != stack_fds) free(fds);
    }
    free(pids);

    // Fallback using lsof for short-lived or race sockets, rate-limited:
    // an unbounded popen per unresolved connection fork-storms under churn.
    static uint32_t s_last_lsof_ms = 0;
    uint32_t now_lsof = get_time_ms();
    if (!found && peer_remote_port > 0 &&
        (s_last_lsof_ms == 0 || now_lsof - s_last_lsof_ms > 2000)) {
        s_last_lsof_ms = now_lsof;
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "lsof -n -P -iTCP:%d -sTCP:ESTABLISHED -F c 2>/dev/null", peer_remote_port);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (line[0] == 'c' && line[1] != '\0') {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    char *pname = line + 1;
                    while (*pname == ' ') pname++;
                    if (*pname) {
                        strncpy(out_name, pname, (size_t)max_len - 1);
                        out_name[max_len - 1] = '\0';
                        found = 1;
                        break;
                    }
                }
            }
            pclose(fp);
        }
    }
    return found;
}

int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;
    out_name[0] = '\0';

    int num_pids = proc_listallpids(NULL, 0);
    if (num_pids <= 0) return 0;

    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * (size_t)num_pids * 2);
    if (!pids) return 0;

    num_pids = proc_listallpids(pids, (int)(sizeof(pid_t) * (size_t)num_pids * 2));
    if (num_pids <= 0) {
        free(pids);
        return 0;
    }

    int found = 0;
    pid_t my_pid = getpid();
    for (int i = 0; i < num_pids && !found; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == my_pid) continue;

        int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (buf_size <= 0) continue;

        struct proc_fdinfo *fds = (struct proc_fdinfo *)malloc((size_t)buf_size);
        if (!fds) continue;

        int num_fds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, buf_size);
        if (num_fds <= 0) {
            free(fds);
            continue;
        }

        int count = num_fds / (int)sizeof(struct proc_fdinfo);
        for (int j = 0; j < count; ++j) {
            if (fds[j].proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo si;
                memset(&si, 0, sizeof(si));
                int s = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
                if (s > (int)sizeof(struct proc_fileinfo)) {
                    int kind = si.psi.soi_kind;
                    if (kind == SOCKINFO_TCP || kind == SOCKINFO_IN || kind == 0) {
                        int raw_lport = (int)(uint16_t)si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
                        int swap_lport = (int)ntohs((uint16_t)raw_lport);
                        if (raw_lport == local_port || swap_lport == local_port) {
                            if (macos_get_proc_name_or_bundle(pid, out_name, max_len)) {
                                found = 1;
                                break;
                            }
                        }
                    }
                }
            }
        }
        free(fds);
    }
    free(pids);
    return found;
}

int alya_vpn_get_udp_process_by_port(int local_port, char *out_name, int max_len) {
    if (!out_name || max_len <= 0) return 0;
    out_name[0] = '\0';

    int num_pids = proc_listallpids(NULL, 0);
    if (num_pids <= 0) return 0;

    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * (size_t)num_pids * 2);
    if (!pids) return 0;

    num_pids = proc_listallpids(pids, (int)(sizeof(pid_t) * (size_t)num_pids * 2));
    if (num_pids <= 0) {
        free(pids);
        return 0;
    }

    int found = 0;
    pid_t my_pid = getpid();
    for (int i = 0; i < num_pids && !found; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == my_pid) continue;

        int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (buf_size <= 0) continue;

        struct proc_fdinfo stack_fds[128];
        struct proc_fdinfo *fds = stack_fds;
        int count = buf_size / (int)sizeof(struct proc_fdinfo);
        if (count > 128) {
            fds = (struct proc_fdinfo *)malloc((size_t)buf_size);
            if (!fds) continue;
        }

        int num_fds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, buf_size);
        if (num_fds <= 0) {
            if (fds != stack_fds) free(fds);
            continue;
        }

        count = num_fds / (int)sizeof(struct proc_fdinfo);
        for (int j = 0; j < count; ++j) {
            if (fds[j].proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo si;
                memset(&si, 0, sizeof(si));
                int s = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
                if (s > (int)sizeof(struct proc_fileinfo)) {
                    // UDP sockets report SOCKINFO_IN with IPPROTO_UDP
                    // (TCP sockets report SOCKINFO_TCP and are skipped here).
                    int kind = si.psi.soi_kind;
                    if ((kind == SOCKINFO_IN || kind == 0) &&
                        si.psi.soi_protocol == IPPROTO_UDP) {
                        int raw_lport = (int)(uint16_t)si.psi.soi_proto.pri_in.insi_lport;
                        int swap_lport = (int)ntohs((uint16_t)raw_lport);
                        if (raw_lport == local_port || swap_lport == local_port) {
                            if (!macos_get_proc_name_or_bundle(pid, out_name, max_len)) {
                                snprintf(out_name, (size_t)max_len, "pid-%d", (int)pid);
                            }
                            found = 1;
                            break;
                        }
                    }
                }
            }
        }
        if (fds != stack_fds) free(fds);
    }
    free(pids);
    return found;
}

#else

int alya_vpn_get_process_by_port(int local_port, char *out_name, int max_len) {
    (void)local_port;
    (void)out_name;
    (void)max_len;
    return 0; // Unsupported platform
}

int alya_vpn_get_process_by_peer_port(int proxy_local_port, int peer_remote_port, char *out_name, int max_len) {
    (void)proxy_local_port;
    (void)peer_remote_port;
    (void)out_name;
    (void)max_len;
    return 0;
}

int alya_vpn_get_udp_process_by_port(int local_port, char *out_name, int max_len) {
    (void)local_port;
    (void)out_name;
    (void)max_len;
    return 0;
}

#endif

static uint32_t get_time_ms(void) {
#if defined(_WIN32)
    return (uint32_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
#endif
}

uint32_t alya_vpn_get_time_ms(void) {
    return get_time_ms();
}

static void close_sock(int s) {
    if (s >= 0) {
#if defined(_WIN32)
        closesocket((SOCKET)s);
#else
        close(s);
#endif
    }
}

static void set_sock_nonblocking(int sock) {
    if (sock < 0) return;
#if defined(_WIN32)
    u_long mode = 1;
    ioctlsocket((SOCKET)sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#if defined(SO_NOSIGPIPE)
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#endif
}

static int s_handshake_timeout_ms = 3000;
static int s_connect_timeout_ms = 3000;
static int s_tcp_nodelay = 1;

void alya_vpn_set_timeouts(int handshake_ms, int connect_ms) {
    if (handshake_ms > 0) s_handshake_timeout_ms = handshake_ms;
    if (connect_ms > 0) s_connect_timeout_ms = connect_ms;
}

void alya_vpn_set_tcp_nodelay(int enable) {
    s_tcp_nodelay = enable ? 1 : 0;
}

int alya_vpn_get_tcp_nodelay(void) {
    return s_tcp_nodelay;
}

static void apply_socket_nodelay(int sock) {
    if (!s_tcp_nodelay || sock < 0) return;
    int opt = 1;
    setsockopt((SOCKET)sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));
}

static void set_socket_timeout(int sock, int timeout_ms) {
    if (sock < 0 || timeout_ms <= 0) return;
#if defined(_WIN32)
    DWORD tv = (DWORD)timeout_ms;
    setsockopt((SOCKET)sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt((SOCKET)sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt((SOCKET)sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt((SOCKET)sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif
}

int alya_vpn_tcp_listen(const char *bind_addr, int port, int backlog) {
    if (port <= 0 || port >= 65536) return -1;
    if (backlog <= 0) backlog = 128;

    int s = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;

#if !defined(_WIN32)
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#if defined(SO_NOSIGPIPE)
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#else
    BOOL opt = TRUE;
    setsockopt((SOCKET)s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (!bind_addr || !bind_addr[0] || strcmp(bind_addr, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(bind_addr);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
    }

    if (bind((SOCKET)s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close_sock(s);
        return -1;
    }

    if (listen((SOCKET)s, backlog) != 0) {
        close_sock(s);
        return -1;
    }

    set_sock_nonblocking(s);
    apply_socket_nodelay(s);
    return s;
}

static int s_srv_log_connections = 1;

void alya_vpn_set_server_log_connections(int enable) {
    s_srv_log_connections = enable ? 1 : 0;
}

int alya_vpn_get_server_log_connections(void) {
    return s_srv_log_connections;
}

static int s_srv_block_lan = 1;

void alya_vpn_set_server_block_lan(int enable) {
    s_srv_block_lan = enable ? 1 : 0;
}

int alya_vpn_get_server_block_lan(void) {
    return s_srv_block_lan;
}

static int s_srv_blocked_ports[64];
static int s_srv_blocked_port_count = 0;

void alya_vpn_server_clear_blocked_ports(void) {
    s_srv_blocked_port_count = 0;
}

void alya_vpn_server_add_blocked_port(int port) {
    if (port <= 0 || port >= 65536 || s_srv_blocked_port_count >= 64) return;
    s_srv_blocked_ports[s_srv_blocked_port_count++] = port;
}

int alya_vpn_server_is_port_blocked(int port) {
    for (int i = 0; i < s_srv_blocked_port_count; ++i) {
        if (s_srv_blocked_ports[i] == port) return 1;
    }
    return 0;
}

static volatile int s_srv_active_clients = 0;
static volatile int s_srv_max_clients = 100;

void alya_vpn_srv_set_max_clients(int max_clients) {
    if (max_clients > 0) s_srv_max_clients = max_clients;
}

int alya_vpn_srv_get_max_clients(void) {
    return s_srv_max_clients;
}

int alya_vpn_srv_get_active_clients(void) {
    return s_srv_active_clients;
}

int alya_vpn_srv_client_connected(void) {
#if defined(_WIN32)
    LONG current = InterlockedCompareExchange((LONG volatile *)&s_srv_active_clients, 0, 0);
    while (current < s_srv_max_clients) {
        LONG old = InterlockedCompareExchange((LONG volatile *)&s_srv_active_clients, current + 1, current);
        if (old == current) return 1;
        current = old;
    }
    return 0;
#elif defined(__GNUC__) || defined(__clang__)
    int current = __atomic_load_n(&s_srv_active_clients, __ATOMIC_RELAXED);
    while (current < s_srv_max_clients) {
        if (__atomic_compare_exchange_n(&s_srv_active_clients, &current, current + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            return 1;
        }
    }
    return 0;
#else
    if (s_srv_active_clients < s_srv_max_clients) {
        s_srv_active_clients++;
        return 1;
    }
    return 0;
#endif
}

void alya_vpn_srv_client_disconnected(void) {
#if defined(_WIN32)
    InterlockedDecrement((LONG volatile *)&s_srv_active_clients);
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_fetch_sub(&s_srv_active_clients, 1, __ATOMIC_RELEASE);
#else
    if (s_srv_active_clients > 0) s_srv_active_clients--;
#endif
}

static int s_idle_timeout_ms = 0;

void alya_vpn_set_idle_timeout_sec(int sec) {
    s_idle_timeout_ms = sec > 0 ? sec * 1000 : 0;
}

int alya_vpn_get_idle_timeout_sec(void) {
    return s_idle_timeout_ms / 1000;
}

static int s_ping_interval_ms = 30000;

void alya_vpn_set_ping_interval_sec(int sec) {
    s_ping_interval_ms = sec > 0 ? sec * 1000 : 0;
}

int alya_vpn_get_ping_interval_sec(void) {
    return s_ping_interval_ms / 1000;
}

static volatile uint64_t s_stats_tx_bytes = 0;
static volatile uint64_t s_stats_rx_bytes = 0;
static volatile uint64_t s_stats_tx_pkts = 0;
static volatile uint64_t s_stats_rx_pkts = 0;

void alya_vpn_stats_add_tx(uint32_t bytes) {
#if defined(_WIN32)
    InterlockedAdd64((LONG64 volatile *)&s_stats_tx_bytes, bytes);
    InterlockedIncrement64((LONG64 volatile *)&s_stats_tx_pkts);
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_fetch_add(&s_stats_tx_bytes, bytes, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_stats_tx_pkts, 1, __ATOMIC_RELAXED);
#else
    s_stats_tx_bytes += bytes;
    s_stats_tx_pkts++;
#endif
}

void alya_vpn_stats_add_rx(uint32_t bytes) {
#if defined(_WIN32)
    InterlockedAdd64((LONG64 volatile *)&s_stats_rx_bytes, bytes);
    InterlockedIncrement64((LONG64 volatile *)&s_stats_rx_pkts);
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_fetch_add(&s_stats_rx_bytes, bytes, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_stats_rx_pkts, 1, __ATOMIC_RELAXED);
#else
    s_stats_rx_bytes += bytes;
    s_stats_rx_pkts++;
#endif
}

void alya_vpn_stats_reset(void) {
    s_stats_tx_bytes = 0;
    s_stats_rx_bytes = 0;
    s_stats_tx_pkts = 0;
    s_stats_rx_pkts = 0;
}

// Forward declarations for the UDP-over-TCP section further below
// (relay socket globals, protocol-mode check, association registry).
static int s_udp_relay_sock;
static int s_udp_relay_port;
static int fwd_allows_udp(void);
static uint32_t assoc_hold(int ctrl_sock);
static int is_would_block(void);

// Deadline-based receive for handshakes. The Alya runtime hands us accepted
// sockets that may already be non-blocking, in which case SO_RCVTIMEO is
// ignored and a single recv() fires before the peer's bytes arrive
// (WSAEWOULDBLOCK / EAGAIN). Loop until min_needed bytes arrive, the peer
// closes, or timeout_ms elapses. Returns bytes buffered (>0), 0 on orderly
// close with nothing read, or -1 on timeout/error.
static int handshake_recv(int sock, unsigned char *buf, int maxlen, int min_needed, int timeout_ms) {
    if (sock < 0 || !buf || maxlen <= 0 || min_needed <= 0) return -1;
    if (timeout_ms <= 0) timeout_ms = 3000;
    uint32_t start = get_time_ms();
    int total = 0;
    while (total < min_needed && total < maxlen) {
        int n = recv((SOCKET)sock, (char *)(buf + total), maxlen - total, 0);
        if (n > 0) {
            total += n;
            continue;
        }
        if (n == 0) {
            return total > 0 ? total : 0; // orderly close
        }
        if (!is_would_block()) return -1; // hard error
        if ((uint32_t)(get_time_ms() - start) >= (uint32_t)timeout_ms) {
            return total > 0 ? total : -1; // timeout
        }
#if defined(_WIN32)
        Sleep(1);
#else
        { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); }
#endif
    }
    return total;
}

int alya_vpn_socks5_handshake(int client_sock, char *out_host, int max_host_len) {    if (!out_host || max_host_len < 16) return -1;

    apply_socket_nodelay(client_sock);
    set_socket_timeout(client_sock, s_handshake_timeout_ms);

    // 1. Initial Greeting / Request peek (deadline-based: accepted sockets
    // may be non-blocking, so a single recv can fire before bytes arrive)
    unsigned char greet[1024];
    int n = handshake_recv(client_sock, greet, (int)sizeof(greet) - 1, 2, s_handshake_timeout_ms);
    if (n < 2) {
        return -1;
    }
    // SOCKS5 greeting declares NMETHODS method bytes; top them up so the
    // request read below never sees leftover method bytes.
    if (greet[0] == 0x05 && n >= 2) {
        int need = 2 + greet[1];
        if (need > n && need < (int)sizeof(greet) - 1) {
            int m = handshake_recv(client_sock, greet + n, (int)sizeof(greet) - 1 - n,
                                   need - n, s_handshake_timeout_ms);
            if (m > 0) n += m;
        }
    }
    greet[n] = '\0';

    // Protocol A: SOCKS5 [0x05, NMETHODS, METHODS...]
    if (greet[0] == 0x05) {
        const unsigned char greet_resp[2] = {0x05, 0x00};
        if (send((SOCKET)client_sock, (const char *)greet_resp, 2, 0) != 2) {
            return -1;
        }

        unsigned char req[512];
        n = handshake_recv(client_sock, req, (int)sizeof(req), 5, s_handshake_timeout_ms);
        if (n < 5 || req[0] != 0x05) {
            const unsigned char fail_resp[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            send((SOCKET)client_sock, (const char *)fail_resp, 10, 0);
            return -1;
        }
        // Complete the request by address type (deadline-based top-up).
        int req_need = 10; // IPv4 default
        if (req[3] == 3) req_need = 5 + req[4] + 2;       // domain
        else if (req[3] == 4) req_need = 22;              // IPv6
        else if (req[3] != 1) req_need = n;               // let ATYP check reject
        if (req_need > n && req_need <= (int)sizeof(req)) {
            int m = handshake_recv(client_sock, req + n, (int)sizeof(req) - n,
                                   req_need - n, s_handshake_timeout_ms);
            if (m > 0) n += m;
        }
        if (n < 7) {
            const unsigned char fail_resp[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            send((SOCKET)client_sock, (const char *)fail_resp, 10, 0);
            return -1;
        }

        // CMD 0x03: UDP ASSOCIATE (RFC 1928). The relay address is returned
        // and the TCP connection is held open as the association control
        // channel (owned by C from here on). Returns -2 as sentinel.
        if (req[1] == 0x03) {
            if (s_udp_relay_sock < 0 || s_udp_relay_port <= 0 || !fwd_allows_udp()) {
                printf("[UDP-DBG] ASSOCIATE reject: relay_sock=%d relay_port=%d allows_udp=%d\n", s_udp_relay_sock, s_udp_relay_port, fwd_allows_udp()); fflush(stdout);
                const unsigned char fail_resp[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                send((SOCKET)client_sock, (const char *)fail_resp, 10, 0);
                return -1;
            }
            unsigned char ok_resp[10] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0};
            ok_resp[8] = (unsigned char)((s_udp_relay_port >> 8) & 0xFF);
            ok_resp[9] = (unsigned char)(s_udp_relay_port & 0xFF);
            send((SOCKET)client_sock, (const char *)ok_resp, 10, 0);
            set_sock_nonblocking(client_sock);
            if (assoc_hold(client_sock) == 0) return -1;
            snprintf(out_host, (size_t)max_host_len, "%s", "udp.associate");
            return -2;
        }

        if (req[1] != 0x01) {
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

    // Non-SOCKS5 protocols need at least 8 bytes for detection
    // ("CONNECT " / SOCKS4 header). Top up with a deadline.
    if (greet[0] != 0x05 && n < 8) {
        int m = handshake_recv(client_sock, greet + n, (int)sizeof(greet) - 1 - n,
                               8 - n, s_handshake_timeout_ms);
        if (m > 0) {
            n += m;
            greet[n] = '\0';
        }
    }

    // Protocol B: HTTP CONNECT (Used by Chrome, Edge, Discord, and system proxy for HTTPS)
    // E.g.: "CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n"
    if (strncmp((const char *)greet, "CONNECT ", 8) == 0) {
        char *p = (char *)greet + 8;
        char *space = strchr(p, ' ');
        if (!space) return -1;
        *space = '\0';

        char *colon = strrchr(p, ':');
        int target_port = 443;
        if (colon) {
            *colon = '\0';
            target_port = atoi(colon + 1);
        }
        snprintf(out_host, (size_t)max_host_len, "%s", p);

        // Read remaining headers until \r\n\r\n if needed (deadline-bounded)
        if (strstr(space + 1, "\r\n\r\n") == NULL) {
            char extra[512];
            uint32_t hstart = get_time_ms();
            while ((uint32_t)(get_time_ms() - hstart) < (uint32_t)s_handshake_timeout_ms) {
                int en = recv((SOCKET)client_sock, extra, sizeof(extra) - 1, 0);
                if (en > 0) {
                    extra[en] = '\0';
                    if (strstr(extra, "\r\n\r\n") != NULL) break;
                    continue;
                }
                if (en == 0) break;
                if (!is_would_block()) break;
#if defined(_WIN32)
                Sleep(1);
#else
                { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); }
#endif
            }
        }

        // Respond: HTTP/1.1 200 Connection Established
        const char *resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send((SOCKET)client_sock, resp, (int)strlen(resp), 0);
        return target_port;
    }

    // Protocol C: SOCKS4 / SOCKS4a [0x04, CMD(0x01), PORT(2), IP(4), USERID..., NULL, (DOMAIN..., NULL)]
    if (greet[0] == 0x04) {
        if (n < 8 || greet[1] != 0x01) {
            const unsigned char fail_resp[8] = {0x00, 0x5b, 0, 0, 0, 0, 0, 0};
            send((SOCKET)client_sock, (const char *)fail_resp, 8, 0);
            return -1;
        }
        int target_port = (greet[2] << 8) | greet[3];
        // SOCKS4a: IP 0.0.0.x with x != 0 -> domain name follows user ID
        if (greet[4] == 0 && greet[5] == 0 && greet[6] == 0 && greet[7] != 0) {
            // Top up with a deadline so a split userid/domain still parses.
            int guard = 0;
            while (guard++ < 4) {
                int ii = 8;
                while (ii < n && greet[ii] != '\0') ii++;
                if (ii < n && ii + 1 < (int)sizeof(greet) - 1) break; // userid NUL seen
                int m = handshake_recv(client_sock, greet + n, (int)sizeof(greet) - 1 - n,
                                       16, s_handshake_timeout_ms);
                if (m <= 0) break;
                n += m;
                greet[n] = '\0';
            }
            int idx = 8;
            while (idx < n && greet[idx] != '\0') idx++;
            idx++; // skip null terminator of user ID
            if (idx < n) {
                snprintf(out_host, (size_t)max_host_len, "%s", (const char *)&greet[idx]);
            } else {
                return -1;
            }
        } else {
            snprintf(out_host, (size_t)max_host_len, "%u.%u.%u.%u", greet[4], greet[5], greet[6], greet[7]);
        }
        const unsigned char ok_resp[8] = {0x00, 0x5a, 0, 0, 0, 0, 0, 0};
        send((SOCKET)client_sock, (const char *)ok_resp, 8, 0);
        return target_port;
    }

    return -1;
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
static int s_tunnel_dns = 1;

static char s_dns_servers[64][64];
static int s_dns_server_count = 0;

static char s_dns_resolvers[32][64];
static int s_dns_resolver_count = 0;

static const char *s_default_dns_servers[] = {
    // Cloudflare DNS
    "1.1.1.1", "1.0.0.1", "one.one.one.one", "cloudflare-dns.com",
    // Google Public DNS
    "8.8.8.8", "8.8.4.4", "dns.google",
    // Quad9 (Malware blocking)
    "9.9.9.9", "149.112.112.112", "dns.quad9.net",
    // AdGuard DNS (Ad & tracker blocking)
    "94.140.14.14", "94.140.15.15", "dns.adguard-dns.com",
    // OpenDNS (Cisco)
    "208.67.222.222", "208.67.220.220",
    // Mullvad DNS
    "194.242.2.2", "194.242.2.3", "dns.mullvad.net",
    // Control D
    "76.76.2.0", "76.76.10.0"
};
#define NUM_DEFAULT_DNS_SERVERS (int)(sizeof(s_default_dns_servers) / sizeof(s_default_dns_servers[0]))

static const char *s_default_dns_resolvers[] = {
    "mDNSResponder",
    "systemd-resolved",
    "dnsmasq",
    "named",
    "resolved",
    "dnscrypt-proxy",
    "stubby",
    "unbound"
};
#define NUM_DEFAULT_DNS_RESOLVERS (int)(sizeof(s_default_dns_resolvers) / sizeof(s_default_dns_resolvers[0]))

void alya_vpn_set_tunnel_dns(int enable) {
    s_tunnel_dns = enable ? 1 : 0;
}

int alya_vpn_get_tunnel_dns(void) {
    return s_tunnel_dns;
}

void alya_vpn_dns_clear(void) {
    s_dns_server_count = 0;
    s_dns_resolver_count = 0;
}

void alya_vpn_add_dns_server(const char *server) {
    if (!server || !server[0] || s_dns_server_count >= 64) return;
    size_t len = strlen(server);
    if (len >= 64) return;
    strncpy(s_dns_servers[s_dns_server_count], server, 63);
    s_dns_servers[s_dns_server_count][63] = '\0';
    s_dns_server_count++;
}

void alya_vpn_add_dns_resolver(const char *resolver) {
    if (!resolver || !resolver[0] || s_dns_resolver_count >= 32) return;
    size_t len = strlen(resolver);
    if (len >= 64) return;
    strncpy(s_dns_resolvers[s_dns_resolver_count], resolver, 63);
    s_dns_resolvers[s_dns_resolver_count][63] = '\0';
    s_dns_resolver_count++;
}

static int s_bypass_lan = 1;
static char s_split_domains[128][128];
static int s_split_domain_count = 0;

void alya_vpn_set_bypass_lan(int enable) {
    s_bypass_lan = enable ? 1 : 0;
}

int alya_vpn_get_bypass_lan(void) {
    return s_bypass_lan;
}

void alya_vpn_domain_clear(void) {
    s_split_domain_count = 0;
}

void alya_vpn_add_routing_domain(const char *domain) {
    if (!domain || !domain[0] || s_split_domain_count >= 128) return;
    size_t len = strlen(domain);
    if (len >= 128) return;
    strncpy(s_split_domains[s_split_domain_count], domain, 127);
    s_split_domains[s_split_domain_count][127] = '\0';
    s_split_domain_count++;
}

static char s_custom_lan_ranges[64][64];
static int s_custom_lan_range_count = 0;

void alya_vpn_clear_custom_lan(void) {
    s_custom_lan_range_count = 0;
}

void alya_vpn_add_custom_lan(const char *range_or_domain) {
    if (!range_or_domain || !range_or_domain[0] || s_custom_lan_range_count >= 64) return;
    size_t len = strlen(range_or_domain);
    if (len >= 64) return;
    strncpy(s_custom_lan_ranges[s_custom_lan_range_count], range_or_domain, 63);
    s_custom_lan_ranges[s_custom_lan_range_count][63] = '\0';
    s_custom_lan_range_count++;
}

static int pattern_match_c(const char *pattern, const char *text);

static int is_lan_target(const char *host) {
    if (!host || !host[0]) return 0;

    if (s_custom_lan_range_count > 0) {
        for (int i = 0; i < s_custom_lan_range_count; ++i) {
            if (pattern_match_c(s_custom_lan_ranges[i], host)) return 1;
            if (strncmp(host, s_custom_lan_ranges[i], strlen(s_custom_lan_ranges[i])) == 0) return 1;
        }
    }

    size_t len = strlen(host);
    if (len >= 6 && ALYA_STRICMP(host + len - 6, ".local") == 0) return 1;
    if (len >= 4 && ALYA_STRICMP(host + len - 4, ".lan") == 0) return 1;
    if (len >= 5 && ALYA_STRICMP(host + len - 5, ".home") == 0) return 1;
    if (len >= 9 && ALYA_STRICMP(host + len - 9, ".internal") == 0) return 1;

    // IPv4 private & link-local ranges
    if (strncmp(host, "10.", 3) == 0) return 1;
    if (strncmp(host, "192.168.", 8) == 0) return 1;
    if (strncmp(host, "169.254.", 8) == 0) return 1;
    if (strncmp(host, "172.", 4) == 0) {
        int sec = atoi(host + 4);
        if (sec >= 16 && sec <= 31) return 1;
    }
    return 0;
}

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

    size_t plen = strlen(pattern);
    size_t tlen = strlen(text);

    // Prefix match with delimiter (e.g. "Discord" or "Discord.exe" matches "Discord Helper", "Discord-Worker")
    char base[128];
    strncpy(base, pattern, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';
    size_t blen = strlen(base);
    if (blen > 4 && ALYA_STRICMP(base + blen - 4, ".exe") == 0) {
        base[blen - 4] = '\0';
        blen -= 4;
    }
    if (blen > 0 && tlen > blen && ALYA_STRNICMP(base, text, blen) == 0) {
        char delim = text[blen];
        if (delim == ' ' || delim == '-' || delim == '_' || delim == '.') {
            return 1;
        }
    }

    // Substring in dot-separated bundle identifiers (e.g. "discord" matches "com.hnc.Discord" or "com.hnc.Discord.ShipIt")
    if (blen >= 3 && strstr(text, ".") != NULL) {
        char p_sub[128], t_sub[256];
        for (size_t i = 0; i <= blen; ++i) p_sub[i] = (char)tolower((unsigned char)base[i]);
        size_t ctlen = tlen < sizeof(t_sub) - 1 ? tlen : sizeof(t_sub) - 1;
        for (size_t i = 0; i < ctlen; ++i) t_sub[i] = (char)tolower((unsigned char)text[i]);
        t_sub[ctlen] = '\0';
        char *hit = strstr(t_sub, p_sub);
        if (hit) {
            int ok_before = (hit == t_sub || *(hit - 1) == '.' || *(hit - 1) == '/' || *(hit - 1) == ' ');
            char after_c = *(hit + blen);
            int ok_after = (after_c == '\0' || after_c == '.' || after_c == ' ' || after_c == '-' || after_c == '_');
            if (ok_before && ok_after) {
                return 1;
            }
        }
    }
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
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
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

    // System DNS resolvers are tunneled if tunnel_dns is enabled
    if (s_tunnel_dns && proc_name && proc_name[0]) {
        if (s_dns_resolver_count > 0) {
            for (int i = 0; i < s_dns_resolver_count; ++i) {
                if (pattern_match_c(s_dns_resolvers[i], proc_name)) {
                    return 1;
                }
            }
        } else {
            for (int i = 0; i < NUM_DEFAULT_DNS_RESOLVERS; ++i) {
                if (pattern_match_c(s_default_dns_resolvers[i], proc_name)) {
                    return 1;
                }
            }
        }
    }

    // In whitelist mode (1), unknown defaults to bypass (0) unless overridden by domain later.
    // In blacklist mode (2), unknown defaults to route (1).
    int is_unknown = (!proc_name || !proc_name[0] || strcmp(proc_name, "unknown") == 0);
    if (is_unknown) {
        return (s_split_mode == 1) ? 0 : 1;
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

int alya_vpn_should_route_host(const char *host, int port) {
    if (s_split_mode == 0) return 1; // route all
    if (!host || !host[0]) return -1;

    // 1. Local loopback must ALWAYS bypass VPN
    if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0 ||
        strcmp(host, "::1") == 0 || strcmp(host, "0.0.0.0") == 0) {
        return 0;
    }

    // 1b. LAN targets (192.168.x, 10.x, 172.16-31.x, .local) bypass VPN if enabled
    if (s_bypass_lan && is_lan_target(host)) {
        return 0;
    }

    // 2. DNS queries route via VPN if tunnel_dns is enabled
    if (s_tunnel_dns) {
        if (port == 53 || port == 853) {
            return 1;
        }
        if (s_dns_server_count > 0) {
            for (int i = 0; i < s_dns_server_count; ++i) {
                if (pattern_match_c(s_dns_servers[i], host)) {
                    return 1;
                }
            }
        } else {
            for (int i = 0; i < NUM_DEFAULT_DNS_SERVERS; ++i) {
                if (pattern_match_c(s_default_dns_servers[i], host)) {
                    return 1;
                }
            }
        }
    }

    // 2b. Match host against explicitly configured routing domains (*.domain.com, etc.)
    if (s_split_domain_count > 0) {
        for (int i = 0; i < s_split_domain_count; ++i) {
            if (pattern_match_c(s_split_domains[i], host)) {
                return (s_split_mode == 2) ? 0 : 1;
            }
        }
    }

    // 3. Match host against configured split apps (e.g. "discord" in "updates.discord.com")
    char host_lower[256];
    size_t hlen = strlen(host);
    if (hlen >= sizeof(host_lower)) hlen = sizeof(host_lower) - 1;
    for (size_t i = 0; i < hlen; ++i) host_lower[i] = (char)tolower((unsigned char)host[i]);
    host_lower[hlen] = '\0';

    int matched = 0;
    for (int i = 0; i < s_split_app_count; ++i) {
        char app_lower[64];
        size_t alen = strlen(s_split_apps[i]);
        if (alen >= sizeof(app_lower)) alen = sizeof(app_lower) - 1;
        for (size_t j = 0; j < alen; ++j) app_lower[j] = (char)tolower((unsigned char)s_split_apps[i][j]);
        app_lower[alen] = '\0';

        // Strip .exe if present
        if (alen > 4 && strcmp(app_lower + alen - 4, ".exe") == 0) {
            app_lower[alen - 4] = '\0';
            alen -= 4;
        }

        // Substring match: e.g. "discord" matches "updates.discord.com", "gateway.discord.gg", "cdn.discordapp.com"
        if (alen > 2 && strstr(host_lower, app_lower) != NULL) {
            matched = 1;
            break;
        }
    }

    if (matched) {
        return (s_split_mode == 1) ? 1 : 0;
    }

    return -1; // No domain-specific override -> use process decision
}

// Small TTL caches: process resolution walks the OS tables on every new
// connection (and per UDP datagram burst). Cache successes briefly; ports
// are recycled slowly, so an 8s TTL cannot misattribute in practice.
#define ALYA_ROUTE_CACHE_N 64
#define ALYA_ROUTE_CACHE_TTL_MS 8000

typedef struct {
    int in_use;
    uint32_t key;
    char name[64];
    uint32_t ts;
} AlyaRouteCacheEntry;

static AlyaRouteCacheEntry s_peer_cache[ALYA_ROUTE_CACHE_N];
static AlyaRouteCacheEntry s_udp_cache[ALYA_ROUTE_CACHE_N];

static int route_cache_get(AlyaRouteCacheEntry *tab, uint32_t key, char *out, int max_len) {
    if (!tab || !out || max_len <= 0) return 0;
    uint32_t now = get_time_ms();
    for (int i = 0; i < ALYA_ROUTE_CACHE_N; ++i) {
        if (tab[i].in_use && tab[i].key == key) {
            if (now - tab[i].ts <= ALYA_ROUTE_CACHE_TTL_MS) {
                strncpy(out, tab[i].name, (size_t)max_len - 1);
                out[max_len - 1] = '\0';
                return 1;
            }
            tab[i].in_use = 0;
            return 0;
        }
    }
    return 0;
}

static void route_cache_put(AlyaRouteCacheEntry *tab, uint32_t key, const char *name) {
    if (!tab || !name || !name[0]) return;
    int slot = -1;
    int i;
    for (i = 0; i < ALYA_ROUTE_CACHE_N; ++i) {
        if (tab[i].in_use && tab[i].key == key) { slot = i; break; }
    }
    if (slot < 0) {
        for (i = 0; i < ALYA_ROUTE_CACHE_N; ++i) {
            if (!tab[i].in_use) { slot = i; break; }
        }
    }
    if (slot < 0) slot = (int)(key % (uint32_t)ALYA_ROUTE_CACHE_N); // full: evict by hash
    tab[slot].in_use = 1;
    tab[slot].key = key;
    strncpy(tab[slot].name, name, sizeof(tab[slot].name) - 1);
    tab[slot].name[sizeof(tab[slot].name) - 1] = '\0';
    tab[slot].ts = get_time_ms();
}

// UPDATED: Now takes both proxy_local_port (the port the VPN proxy listens on)
// and peer_remote_port (the client's ephemeral source port).
// Uses the new alya_vpn_get_process_by_peer_port which matches BOTH ports.
int alya_vpn_check_peer_route(int proxy_local_port, int peer_remote_port, char *out_proc_name, int max_len) {
    if (!out_proc_name || max_len <= 0) return 1;
    out_proc_name[0] = '\0';
    uint32_t key = ((uint32_t)(proxy_local_port & 0xFFFF) << 16) | (uint32_t)(peer_remote_port & 0xFFFF);
    if (route_cache_get(s_peer_cache, key, out_proc_name, max_len)) {
        return alya_vpn_should_route(out_proc_name);
    }
    int res = alya_vpn_get_process_by_peer_port(proxy_local_port, peer_remote_port, out_proc_name, max_len);
    if (!res || !out_proc_name[0]) {
        strncpy(out_proc_name, "unknown", (size_t)max_len - 1);
        out_proc_name[max_len - 1] = '\0';
    } else {
        route_cache_put(s_peer_cache, key, out_proc_name);
    }
    return alya_vpn_should_route(out_proc_name);
}

int alya_vpn_infer_process_from_host(const char *host, char *out_proc_name, int max_len) {
    if (!host || !host[0] || !out_proc_name || max_len <= 0) return 0;
    out_proc_name[0] = '\0';

    char host_lower[256];
    size_t hlen = strlen(host);
    if (hlen >= sizeof(host_lower)) hlen = sizeof(host_lower) - 1;
    for (size_t i = 0; i < hlen; ++i) host_lower[i] = (char)tolower((unsigned char)host[i]);
    host_lower[hlen] = '\0';

    for (int i = 0; i < s_split_app_count; ++i) {
        char app_lower[64];
        size_t alen = strlen(s_split_apps[i]);
        if (alen >= sizeof(app_lower)) alen = sizeof(app_lower) - 1;
        for (size_t j = 0; j < alen; ++j) app_lower[j] = (char)tolower((unsigned char)s_split_apps[i][j]);
        app_lower[alen] = '\0';

        if (alen > 4 && strcmp(app_lower + alen - 4, ".exe") == 0) {
            app_lower[alen - 4] = '\0';
            alen -= 4;
        }

        if (alen > 2 && strstr(host_lower, app_lower) != NULL) {
            strncpy(out_proc_name, s_split_apps[i], (size_t)max_len - 1);
            out_proc_name[max_len - 1] = '\0';
            return 1;
        }
    }

    return 0;
}


// ============================================================================
// Native Channel & Direct Connection Tables (O(1) lookup, 0 heap allocations)
// ============================================================================

#define ALYA_MAX_CHANNELS 2048

typedef struct {
    int in_use;
    int channel_id;
    int app_sock;
    uint32_t last_activity_ms;
} AlyaChannelEntry;

typedef struct {
    int in_use;
    int connecting;
    uint32_t connect_start_ms;
    int app_sock;
    int dest_sock;
    uint32_t last_activity_ms;
} AlyaDirectEntry;

typedef struct {
    int in_use;
    int channel_id;
    int dest_sock;
    uint32_t last_activity_ms;
} AlyaSrvChannelEntry;

static AlyaChannelEntry s_client_channels[ALYA_MAX_CHANNELS];
static AlyaDirectEntry s_client_directs[ALYA_MAX_CHANNELS];
static ALYA_THREAD_LOCAL AlyaSrvChannelEntry s_server_channels[ALYA_MAX_CHANNELS];

const char *alya_vpn_stats_get_summary(void) {
    static char s_stats_buf[256];
    double tx_mb = (double)s_stats_tx_bytes / (1024.0 * 1024.0);
    double rx_mb = (double)s_stats_rx_bytes / (1024.0 * 1024.0);
    int ch_count = alya_vpn_ch_count() + alya_vpn_direct_count() + alya_vpn_srv_ch_count();
    snprintf(s_stats_buf, sizeof(s_stats_buf),
             "Channels: %d | TX: %.2f MB (%llu pkts) | RX: %.2f MB (%llu pkts)",
             ch_count, tx_mb, (unsigned long long)s_stats_tx_pkts, rx_mb, (unsigned long long)s_stats_rx_pkts);
    return s_stats_buf;
}

static int is_would_block(void) {
    int err = 0;
#if defined(_WIN32)
    err = WSAGetLastError();
    return (err == WSAEWOULDBLOCK);
#else
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
#endif
}

static int send_all(int sock, const uint8_t *buf, int len) {
    if (sock < 0 || !buf || len <= 0) return 0;
    int total = 0;
    int retries = 0;
    while (total < len) {
        int s = send((SOCKET)sock, (const char *)(buf + total), len - total, 0);
        if (s > 0) {
            total += s;
            retries = 0;
        } else if (s <= 0) {
            if (is_would_block()) {
                retries++;
                if (retries > 500) {
                    return -1;
                }
#if defined(_WIN32)
                Sleep(1);
#else
                struct timespec ts = {0, 1000000};
                nanosleep(&ts, NULL);
#endif
                continue;
            }
            return -1;
        }
    }
    return total;
}

static int connect_target(const char *host, int port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Prefer IPv4 to avoid 75-second IPv6 blackhole hangs
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        // Fall back to AF_UNSPEC if IPv4 lookup returned nothing
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
            return -1;
        }
    }

    int target_sock = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        int s = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
#if defined(SO_NOSIGPIPE)
        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        apply_socket_nodelay(s);
        set_socket_timeout(s, s_connect_timeout_ms);

        if (connect((SOCKET)s, p->ai_addr, (int)p->ai_addrlen) == 0) {
            target_sock = s;
            break;
        }
        close_sock(s);
    }

    freeaddrinfo(res);
    return target_sock;
}

static int connect_target_async(const char *host, int port, int *out_connecting) {
    if (out_connecting) *out_connecting = 0;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Prefer IPv4 to avoid 75-second IPv6 blackhole hangs
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
            return -1;
        }
    }

    int target_sock = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        int s = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
#if defined(SO_NOSIGPIPE)
        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        set_sock_nonblocking(s);
        apply_socket_nodelay(s);

        int cr = connect((SOCKET)s, p->ai_addr, (int)p->ai_addrlen);
        if (cr == 0) {
            target_sock = s;
            if (out_connecting) *out_connecting = 0;
            break;
        } else {
#if defined(_WIN32)
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                target_sock = s;
                if (out_connecting) *out_connecting = 1;
                break;
            }
#else
            if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
                target_sock = s;
                if (out_connecting) *out_connecting = 1;
                break;
            }
#endif
            close_sock(s);
        }
    }

    freeaddrinfo(res);
    return target_sock;
}

static uint8_t s_vpn_client_rx[131072];
static int s_vpn_client_rx_len = 0;

static ALYA_THREAD_LOCAL uint8_t s_srv_rx[131072];
static ALYA_THREAD_LOCAL int s_srv_rx_len = 0;

// Client Channel Table
void alya_vpn_ch_set(int channel_id, int app_sock) {
    set_sock_nonblocking(app_sock);
    int free_slot = -1;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_channels[i].in_use && s_client_channels[i].channel_id == channel_id) {
            s_client_channels[i].app_sock = app_sock;
            s_client_channels[i].last_activity_ms = get_time_ms();
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
        s_client_channels[free_slot].last_activity_ms = get_time_ms();
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
    s_vpn_client_rx_len = 0;
}

// Client Direct Connections
void alya_vpn_direct_set_connecting(int app_sock, int dest_sock, int connecting) {
    set_sock_nonblocking(app_sock);
    set_sock_nonblocking(dest_sock);
    int free_slot = -1;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_client_directs[i].in_use && s_client_directs[i].app_sock == app_sock) {
            s_client_directs[i].dest_sock = dest_sock;
            s_client_directs[i].connecting = connecting;
            s_client_directs[i].connect_start_ms = get_time_ms();
            s_client_directs[i].last_activity_ms = get_time_ms();
            return;
        }
        if (!s_client_directs[i].in_use && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        s_client_directs[free_slot].in_use = 1;
        s_client_directs[free_slot].app_sock = app_sock;
        s_client_directs[free_slot].dest_sock = dest_sock;
        s_client_directs[free_slot].connecting = connecting;
        s_client_directs[free_slot].connect_start_ms = get_time_ms();
        s_client_directs[free_slot].last_activity_ms = get_time_ms();
    }
}

void alya_vpn_direct_set(int app_sock, int dest_sock) {
    alya_vpn_direct_set_connecting(app_sock, dest_sock, 0);
}

int alya_vpn_pump_direct(void) {
    int activity = 0;
    static char buf[65536];
    uint32_t now = get_time_ms();

    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (!s_client_directs[i].in_use) continue;
        int a_sock = s_client_directs[i].app_sock;
        int d_sock = s_client_directs[i].dest_sock;
        if (a_sock < 0 || d_sock < 0) continue;

        // Check if asynchronous connect is in progress
        if (s_client_directs[i].connecting) {
            uint32_t conn_timeout = (s_connect_timeout_ms > 0) ? (uint32_t)s_connect_timeout_ms : 3000;
            if (now - s_client_directs[i].connect_start_ms > conn_timeout) {
                // Timeout after configured connect_timeout_ms
                close_sock(a_sock);
                close_sock(d_sock);
                s_client_directs[i].in_use = 0;
                s_client_directs[i].app_sock = -1;
                s_client_directs[i].dest_sock = -1;
                continue;
            }
#if defined(_WIN32)
            fd_set wfds, efds;
            FD_ZERO(&wfds);
            FD_ZERO(&efds);
            FD_SET((SOCKET)d_sock, &wfds);
            FD_SET((SOCKET)d_sock, &efds);
            struct timeval tv = {0, 0};
            int sel = select(0, NULL, &wfds, &efds, &tv);
            if (sel > 0) {
                if (FD_ISSET((SOCKET)d_sock, &efds)) {
                    close_sock(a_sock);
                    close_sock(d_sock);
                    s_client_directs[i].in_use = 0;
                    s_client_directs[i].app_sock = -1;
                    s_client_directs[i].dest_sock = -1;
                    continue;
                }
                if (FD_ISSET((SOCKET)d_sock, &wfds)) {
                    s_client_directs[i].connecting = 0;
                    activity = 1;
                }
            } else {
                continue; // Still connecting
            }
#else
            struct pollfd pfd;
            pfd.fd = d_sock;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int pr = poll(&pfd, 1, 0);
            if (pr > 0) {
                if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    close_sock(a_sock);
                    close_sock(d_sock);
                    s_client_directs[i].in_use = 0;
                    s_client_directs[i].app_sock = -1;
                    s_client_directs[i].dest_sock = -1;
                    continue;
                }
                if (pfd.revents & POLLOUT) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    if (getsockopt(d_sock, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
                        s_client_directs[i].connecting = 0;
                        activity = 1;
                    } else {
                        close_sock(a_sock);
                        close_sock(d_sock);
                        s_client_directs[i].in_use = 0;
                        s_client_directs[i].app_sock = -1;
                        s_client_directs[i].dest_sock = -1;
                        continue;
                    }
                }
            } else {
                continue; // Still connecting
            }
#endif
        }

        // Idle timeout check for direct connection
        if (s_idle_timeout_ms > 0 && !s_client_directs[i].connecting &&
            (now - s_client_directs[i].last_activity_ms > (uint32_t)s_idle_timeout_ms)) {
            close_sock(a_sock);
            close_sock(d_sock);
            s_client_directs[i].in_use = 0;
            s_client_directs[i].app_sock = -1;
            s_client_directs[i].dest_sock = -1;
            continue;
        }

        // 1. App -> Destination (uploading request / data / photos)
        int n1 = recv((SOCKET)a_sock, buf, sizeof(buf), 0);
        if (n1 > 0) {
            activity = 1;
            s_client_directs[i].last_activity_ms = now;
            alya_vpn_stats_add_tx((uint32_t)n1);
            if (send_all(d_sock, (const uint8_t *)buf, n1) < 0) {
                close_sock(a_sock);
                close_sock(d_sock);
                s_client_directs[i].in_use = 0;
                s_client_directs[i].app_sock = -1;
                s_client_directs[i].dest_sock = -1;
                continue;
            }
        } else if (n1 == 0) {
            // EOF: client closed
            close_sock(a_sock);
            close_sock(d_sock);
            s_client_directs[i].in_use = 0;
            s_client_directs[i].app_sock = -1;
            s_client_directs[i].dest_sock = -1;
            continue;
        } else {
            if (!is_would_block()) {
                close_sock(a_sock);
                close_sock(d_sock);
                s_client_directs[i].in_use = 0;
                s_client_directs[i].app_sock = -1;
                s_client_directs[i].dest_sock = -1;
                continue;
            }
        }

        // 2. Destination -> App (downloading response / media)
        int n2 = recv((SOCKET)d_sock, buf, sizeof(buf), 0);
        if (n2 > 0) {
            activity = 1;
            s_client_directs[i].last_activity_ms = now;
            alya_vpn_stats_add_rx((uint32_t)n2);
            if (send_all(a_sock, (const uint8_t *)buf, n2) < 0) {
                close_sock(a_sock);
                close_sock(d_sock);
                s_client_directs[i].in_use = 0;
                s_client_directs[i].app_sock = -1;
                s_client_directs[i].dest_sock = -1;
                continue;
            }
        } else if (n2 == 0) {
            // EOF: destination closed
            close_sock(a_sock);
            close_sock(d_sock);
            s_client_directs[i].in_use = 0;
            s_client_directs[i].app_sock = -1;
            s_client_directs[i].dest_sock = -1;
        } else {
            if (!is_would_block()) {
                close_sock(a_sock);
                close_sock(d_sock);
                s_client_directs[i].in_use = 0;
                s_client_directs[i].app_sock = -1;
                s_client_directs[i].dest_sock = -1;
            }
        }
    }

    return activity;
}

int alya_vpn_open_direct(int app_sock, const char *host, int port) {
    if (app_sock < 0 || !host || !host[0] || port <= 0) return -1;
    int connecting = 0;
    int dest_sock = connect_target_async(host, port, &connecting);
    if (dest_sock < 0) {
        return -1;
    }
    set_sock_nonblocking(app_sock);
    set_sock_nonblocking(dest_sock);
    alya_vpn_direct_set_connecting(app_sock, dest_sock, connecting);
    return dest_sock;
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

// ============================================================================
// Forward Protocol Mode (tcp / udp / both) + UDP-over-TCP Tunnel
// ============================================================================
// The client<->server tunnel itself always runs over TCP (DPI-friendly).
// This mode controls which *forwarded payload types* are allowed:
//   1 = TCP only, 2 = UDP only, 3 = both (default).
// UDP datagrams are encapsulated in AV02 UDP_DATA frames (UDP-over-TCP),
// the same technique used by Shadowsocks / V2Ray / OpenVPN-TCP.

static int s_fwd_protocol = 3;

void alya_vpn_set_forward_protocol(int mode) {
    if (mode >= 1 && mode <= 3) s_fwd_protocol = mode;
}

int alya_vpn_get_forward_protocol(void) {
    return s_fwd_protocol;
}

static int fwd_allows_tcp(void) { return (s_fwd_protocol == 1 || s_fwd_protocol == 3); }
static int fwd_allows_udp(void) { return (s_fwd_protocol == 2 || s_fwd_protocol == 3); }

// --- UDP payload codec: [port u16BE][hlen u16BE][host bytes][datagram] ---
static int udp_payload_encode(uint8_t *out, int max_out, const char *host, int port,
                              const uint8_t *data, int dlen) {
    if (!out || !host || !data || port <= 0 || port >= 65536) return -1;
    int hlen = (int)strlen(host);
    if (hlen <= 0 || hlen > 255 || dlen < 0) return -1;
    if (4 + hlen + dlen > max_out) return -1;
    out[0] = (uint8_t)((port >> 8) & 0xFF);
    out[1] = (uint8_t)(port & 0xFF);
    out[2] = (uint8_t)((hlen >> 8) & 0xFF);
    out[3] = (uint8_t)(hlen & 0xFF);
    memcpy(out + 4, host, (size_t)hlen);
    if (dlen > 0) memcpy(out + 4 + hlen, data, (size_t)dlen);
    return 4 + hlen + dlen;
}

static int udp_payload_decode(const uint8_t *p, uint32_t plen, char *host_out, int host_max,
                              int *port_out, const uint8_t **data_out, int *dlen_out) {
    if (!p || plen < 4 || !host_out || host_max <= 0 || !port_out || !data_out || !dlen_out) return -1;
    int port = (p[0] << 8) | p[1];
    int hlen = (p[2] << 8) | p[3];
    if (port <= 0 || port >= 65536 || hlen <= 0 || hlen >= host_max) return -1;
    if (4 + (uint32_t)hlen > plen) return -1;
    memcpy(host_out, p + 4, (size_t)hlen);
    host_out[hlen] = '\0';
    *port_out = port;
    *data_out = p + 4 + hlen;
    *dlen_out = (int)(plen - 4 - (uint32_t)hlen);
    return 0;
}

// --- UDP socket helpers ---
static int udp_bind_socket(const char *bind_addr, int port) {
    int s = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
#if !defined(_WIN32)
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (!bind_addr || !bind_addr[0] || strcmp(bind_addr, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(bind_addr);
        if (addr.sin_addr.s_addr == INADDR_NONE) addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind((SOCKET)s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close_sock(s);
        return -1;
    }
    set_sock_nonblocking(s);
    return s;
}

// Connected (filtered) UDP socket to a resolved target. Returns sock or -1.
static int connect_udp_target(const char *host, int port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;
    }
    int s = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        int fd = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
#if defined(SO_NOSIGPIPE)
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        set_sock_nonblocking(fd);
        if (connect((SOCKET)fd, p->ai_addr, (int)p->ai_addrlen) == 0) { s = fd; break; }
#if !defined(_WIN32)
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) { s = fd; break; }
#else
        { int err = WSAGetLastError(); if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) { s = fd; break; } }
#endif
        close_sock(fd);
    }
    freeaddrinfo(res);
    return s;
}

static uint32_t udp_effective_idle_ms(void) {
    if (s_idle_timeout_ms > 0) return (uint32_t)s_idle_timeout_ms;
    return 120000; // 120s default for datagram associations
}

// --- SOCKS5 UDP header codec (RFC 1928: RSV(2) FRAG(1) ATYP ADR PORT DATA) ---
// Parses one relay datagram. Returns 0 on ok (FRAG must be 0).
static int socks5_udp_parse(const uint8_t *buf, int blen, char *host_out, int host_max, int *port_out,
                            const uint8_t **data_out, int *dlen_out) {
    if (!buf || blen < 10 || !host_out || !port_out || !data_out || !dlen_out) return -1;
    if (buf[2] != 0) return -1; // fragmentation not supported
    int atyp = buf[3];
    int off = 4;
    if (atyp == 1) {
        if (blen < off + 4 + 2) return -1;
        snprintf(host_out, (size_t)host_max, "%u.%u.%u.%u", buf[4], buf[5], buf[6], buf[7]);
        off += 4;
    } else if (atyp == 3) {
        int dlen = buf[4];
        if (dlen <= 0 || blen < off + 1 + dlen + 2 || dlen >= host_max) return -1;
        memcpy(host_out, buf + 5, (size_t)dlen);
        host_out[dlen] = '\0';
        off += 1 + dlen;
    } else if (atyp == 4) {
        if (blen < off + 16 + 2) return -1;
        if (!inet_ntop(AF_INET6, buf + off, host_out, (socklen_t)host_max)) return -1;
        off += 16;
    } else {
        return -1;
    }
    *port_out = (buf[off] << 8) | buf[off + 1];
    off += 2;
    if (*port_out <= 0 || *port_out >= 65536 || off > blen) return -1;
    *data_out = buf + off;
    *dlen_out = blen - off;
    return 0;
}

// Builds a relay->app datagram. Returns bytes written or -1.
static int socks5_udp_build(uint8_t *out, int max_out, const char *host, int port,
                            const uint8_t *data, int dlen) {
    if (!out || !host || !data || dlen < 0) return -1;
    unsigned int a, b, c, d;
    int is_v4 = (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256);
    int hlen = (int)strlen(host);
    int need = is_v4 ? (4 + 4 + 2 + dlen) : (4 + 1 + hlen + 2 + dlen);
    if (hlen <= 0 || hlen > 255 || need > max_out) return -1;
    out[0] = 0; out[1] = 0; out[2] = 0;
    int off = 3;
    if (is_v4) {
        out[off++] = 1;
        out[off++] = (uint8_t)a; out[off++] = (uint8_t)b; out[off++] = (uint8_t)c; out[off++] = (uint8_t)d;
    } else {
        out[off++] = 3;
        out[off++] = (uint8_t)hlen;
        memcpy(out + off, host, (size_t)hlen);
        off += hlen;
    }
    out[off++] = (uint8_t)((port >> 8) & 0xFF);
    out[off++] = (uint8_t)(port & 0xFF);
    if (dlen > 0) memcpy(out + off, data, (size_t)dlen);
    return off + dlen;
}

// ============================================================================
// Client-side UDP relay (SOCKS5 UDP ASSOCIATE target) + associations
// ============================================================================
// The relay socket lives in C because the Alya std/net API is TCP-only.
// Ownership rule: once the handshake reports UDP ASSOCIATE, the TCP control
// socket is owned by C (Alya layer must NOT close it). Teardown closes it.

#define ALYA_MAX_ASSOC 64
#define ALYA_MAX_UDP_CH 512

typedef struct {
    int in_use;
    uint32_t assoc_id;
    int ctrl_sock; // SOCKS5 TCP control connection (kept open per RFC 1928)
    int synced;    // ASSOC_REQ already transmitted on the tunnel
} AlyaAssocEntry;

typedef struct {
    int in_use;
    uint32_t assoc_id;
    char target_host[256];
    int target_port;
    struct sockaddr_in app_src; // where to deliver replies
    uint32_t last_activity_ms;
} AlyaClientUdpEntry;

typedef struct {
    int in_use;
    struct sockaddr_in app_src;
    char target_host[256];
    int target_port;
    int udp_sock; // connected UDP socket for direct (bypass) forwarding
    uint32_t last_activity_ms;
} AlyaDirectUdpEntry;

static int s_udp_relay_sock = -1;
static int s_udp_relay_port = -1;
static AlyaAssocEntry s_assocs[ALYA_MAX_ASSOC];
static AlyaClientUdpEntry s_client_udp[ALYA_MAX_UDP_CH];
static AlyaDirectUdpEntry s_direct_udp[ALYA_MAX_UDP_CH];
static uint32_t s_next_assoc_id = 1;
static uint64_t s_udp_tx_drops = 0;

int alya_vpn_udp_relay_init(const char *bind_addr, int port) {
    if (s_udp_relay_sock >= 0) return s_udp_relay_port;
    int s = udp_bind_socket(bind_addr, port);
    if (s < 0 && port != 0) s = udp_bind_socket(bind_addr, 0); // ephemeral fallback
    if (s < 0) return -1;
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname((SOCKET)s, (struct sockaddr *)&bound, &blen) == 0) {
        s_udp_relay_port = (int)ntohs(bound.sin_port);
    } else {
        s_udp_relay_port = port;
    }
    s_udp_relay_sock = s;
    return s_udp_relay_port;
}

int alya_vpn_udp_relay_port(void) {
    return s_udp_relay_port;
}

// Registers a SOCKS5 UDP ASSOCIATE control socket. Returns assoc id or 0.
static uint32_t assoc_hold(int ctrl_sock) {
    set_sock_nonblocking(ctrl_sock);
    for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
        if (!s_assocs[i].in_use) {
            uint32_t id = s_next_assoc_id++;
            if (s_next_assoc_id == 0) s_next_assoc_id = 1;
            if (id == 0) id = s_next_assoc_id++;
            s_assocs[i].in_use = 1;
            s_assocs[i].assoc_id = id;
            s_assocs[i].ctrl_sock = ctrl_sock;
            s_assocs[i].synced = 0;
            return id;
        }
    }
    return 0;
}

static AlyaAssocEntry *assoc_find(uint32_t id) {
    for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
        if (s_assocs[i].in_use && s_assocs[i].assoc_id == id) return &s_assocs[i];
    }
    return NULL;
}

static void client_udp_remove_assoc(uint32_t assoc_id) {
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_client_udp[i].in_use && s_client_udp[i].assoc_id == assoc_id) {
            memset(&s_client_udp[i], 0, sizeof(s_client_udp[i]));
        }
    }
}

static void assoc_remove(uint32_t id) {
    AlyaAssocEntry *a = assoc_find(id);
    if (a) {
        if (a->ctrl_sock >= 0) close_sock(a->ctrl_sock);
        memset(a, 0, sizeof(*a));
    }
    client_udp_remove_assoc(id);
}

// Marks all associations unsynced so ASSOC_REQ is re-transmitted on the
// new tunnel after a reconnect (mirrors the TCP ch_clear behavior).
void alya_vpn_udp_resync(void) {
    for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
        if (s_assocs[i].in_use) s_assocs[i].synced = 0;
    }
}

void alya_vpn_udp_clear(void) {    for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
        if (s_assocs[i].in_use && s_assocs[i].ctrl_sock >= 0) close_sock(s_assocs[i].ctrl_sock);
    }
    memset(s_assocs, 0, sizeof(s_assocs));
    memset(s_client_udp, 0, sizeof(s_client_udp));
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_direct_udp[i].in_use && s_direct_udp[i].udp_sock >= 0) close_sock(s_direct_udp[i].udp_sock);
    }
    memset(s_direct_udp, 0, sizeof(s_direct_udp));
    if (s_udp_relay_sock >= 0) { close_sock(s_udp_relay_sock); s_udp_relay_sock = -1; s_udp_relay_port = -1; }
}

static AlyaClientUdpEntry *client_udp_find_or_create(uint32_t assoc_id, const char *host, int port,
                                                     const struct sockaddr_in *src) {
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_client_udp[i].in_use && s_client_udp[i].assoc_id == assoc_id &&
            s_client_udp[i].target_port == port && strcmp(s_client_udp[i].target_host, host) == 0) {
            s_client_udp[i].app_src = *src;
            s_client_udp[i].last_activity_ms = get_time_ms();
            return &s_client_udp[i];
        }
    }
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (!s_client_udp[i].in_use) {
            s_client_udp[i].in_use = 1;
            s_client_udp[i].assoc_id = assoc_id;
            strncpy(s_client_udp[i].target_host, host, sizeof(s_client_udp[i].target_host) - 1);
            s_client_udp[i].target_port = port;
            s_client_udp[i].app_src = *src;
            s_client_udp[i].last_activity_ms = get_time_ms();
            return &s_client_udp[i];
        }
    }
    return NULL;
}

static AlyaDirectUdpEntry *direct_udp_find_or_create(const struct sockaddr_in *src,
                                                     const char *host, int port) {
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_direct_udp[i].in_use && s_direct_udp[i].target_port == port &&
            strcmp(s_direct_udp[i].target_host, host) == 0 &&
            s_direct_udp[i].app_src.sin_addr.s_addr == src->sin_addr.s_addr &&
            s_direct_udp[i].app_src.sin_port == src->sin_port) {
            s_direct_udp[i].last_activity_ms = get_time_ms();
            return &s_direct_udp[i];
        }
    }
    int s = connect_udp_target(host, port);
    if (s < 0) return NULL;
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (!s_direct_udp[i].in_use) {
            s_direct_udp[i].in_use = 1;
            s_direct_udp[i].app_src = *src;
            strncpy(s_direct_udp[i].target_host, host, sizeof(s_direct_udp[i].target_host) - 1);
            s_direct_udp[i].target_port = port;
            s_direct_udp[i].udp_sock = s;
            s_direct_udp[i].last_activity_ms = get_time_ms();
            return &s_direct_udp[i];
        }
    }
    close_sock(s);
    return NULL;
}

// Relay -> tunnel (+ direct bypass) pump. Called from the Alya client loop
// after alya_vpn_pump_client_vpn. Returns 1 on activity, 0 when idle.
int64_t alya_vpn_pump_client_udp_out(int vpn_sock) {
    if (s_udp_relay_sock < 0 || !fwd_allows_udp()) return 0;
    int activity = 0;
    uint32_t now = get_time_ms();
    uint32_t idle_ms = udp_effective_idle_ms();

    // 1. Poll ASSOCIATE control sockets (RFC 1928: assoc ends with TCP close)
    for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
        if (!s_assocs[i].in_use) continue;
        char tmp[64];
        int n = recv((SOCKET)s_assocs[i].ctrl_sock, tmp, sizeof(tmp), MSG_PEEK);
        if (n == 0) {
            assoc_remove(s_assocs[i].assoc_id);
            activity = 1;
        } else if (n > 0) {
            recv((SOCKET)s_assocs[i].ctrl_sock, tmp, sizeof(tmp), 0); // drain (never sent by clients)
            activity = 1;
        } else if (!is_would_block()) {
            assoc_remove(s_assocs[i].assoc_id);
            activity = 1;
        }
    }

    // 2. Sync new associations on the tunnel
    if (vpn_sock >= 0) {
        for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
            if (s_assocs[i].in_use && !s_assocs[i].synced) {
                uint8_t fr[ALYA_AV02_HEADER_LEN + 16];
                int flen = alya_vpn_pack_frame_av02(ALYA_AV02_MSG_UDP_ASSOC_REQ,
                                                    s_assocs[i].assoc_id, NULL, 0,
                                                    fr, sizeof(fr));
                if (flen > 0 && send_all(vpn_sock, fr, flen) == flen) {
                    s_assocs[i].synced = 1;
                    activity = 1;
                }
            }
        }
    }

    // 3. Drain relay datagrams (cap per tick to bound latency)
    static uint8_t rbuf[65535];
    static uint8_t frbuf[ALYA_AV02_HEADER_LEN + 32768];
    for (int iter = 0; iter < 32; ++iter) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int n = recvfrom((SOCKET)s_udp_relay_sock, (char *)rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&src, &slen);
        if (n <= 0) {
            if (n < 0 && !is_would_block()) return activity;
            break;
        }
        activity = 1;
        char host[256]; int port = 0;
        const uint8_t *dg = NULL; int dglen = 0;
        if (socks5_udp_parse(rbuf, n, host, sizeof(host), &port, &dg, &dglen) != 0) continue;
        if (dglen > 32000) { s_udp_tx_drops++; continue; }

        // Split-tunnel decision mirrors the TCP path: host rule wins,
        // otherwise fall back to the UDP sender's process.
        int decision;
        int hr = alya_vpn_should_route_host(host, port);
        if (hr == 1) decision = 1;
        else if (hr == 0) decision = 0;
        else {
            char pname[256] = {0};
            int src_port = (int)ntohs(src.sin_port);
            uint32_t ukey = (uint32_t)(src_port & 0xFFFF);
            if (!route_cache_get(s_udp_cache, ukey, pname, sizeof(pname))) {
                if (!alya_vpn_get_udp_process_by_port(src_port, pname, sizeof(pname)) || !pname[0]) {
                    strncpy(pname, "unknown", sizeof(pname) - 1);
                } else {
                    route_cache_put(s_udp_cache, ukey, pname);
                }
            }
            decision = alya_vpn_should_route(pname);
        }

        // Find owning association by source port: datagrams arriving at the
        // relay without an association are dropped (strict RFC 1928).
        uint32_t assoc_id = 0;
        for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
            if (s_client_udp[i].in_use &&
                s_client_udp[i].app_src.sin_addr.s_addr == src.sin_addr.s_addr &&
                s_client_udp[i].app_src.sin_port == src.sin_port) {
                assoc_id = s_client_udp[i].assoc_id;
                break;
            }
        }
        if (assoc_id == 0) {
            // First datagram of a new (assoc, target): attribute to the most
            // recently synced association from the same source IP.
            for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
                if (s_assocs[i].in_use && s_assocs[i].synced) { assoc_id = s_assocs[i].assoc_id; break; }
            }
            if (assoc_id == 0) continue;
        }

        if (decision == 0) {
            // Direct bypass: forward locally, replies demultiplexed by target.
            AlyaDirectUdpEntry *de = direct_udp_find_or_create(&src, host, port);
            if (de && dglen > 0) {
                if (send((SOCKET)de->udp_sock, (const char *)dg, dglen, 0) == dglen) {
                    de->last_activity_ms = now;
                    alya_vpn_stats_add_tx((uint32_t)dglen);
                }
            }
            if (!client_udp_find_or_create(assoc_id, host, port, &src)) { s_udp_tx_drops++; }
            continue;
        }

        if (vpn_sock < 0) continue;
        AlyaAssocEntry *a = assoc_find(assoc_id);
        if (!a || !a->synced) continue;
        if (!client_udp_find_or_create(assoc_id, host, port, &src)) { s_udp_tx_drops++; continue; }
        uint8_t *pl = frbuf + ALYA_AV02_HEADER_LEN;
        int plw = udp_payload_encode(pl, (int)sizeof(frbuf) - ALYA_AV02_HEADER_LEN, host, port, dg, dglen);
        if (plw < 0) { s_udp_tx_drops++; continue; }
        int flen = alya_vpn_pack_frame_av02(ALYA_AV02_MSG_UDP_DATA, assoc_id, pl, (uint32_t)plw,
                                            frbuf, sizeof(frbuf));
        if (flen > 0 && send_all(vpn_sock, frbuf, flen) == flen) {
            alya_vpn_stats_add_tx((uint32_t)dglen);
        }
    }

    // 4. Direct-bypass replies -> app
    static uint8_t dbuf[65535];
    static uint8_t obuf[65535];
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (!s_direct_udp[i].in_use) continue;
        if (now - s_direct_udp[i].last_activity_ms > idle_ms) {
            close_sock(s_direct_udp[i].udp_sock);
            memset(&s_direct_udp[i], 0, sizeof(s_direct_udp[i]));
            continue;
        }
        int n = recv((SOCKET)s_direct_udp[i].udp_sock, (char *)dbuf, sizeof(dbuf), 0);
        if (n > 0) {
            activity = 1;
            s_direct_udp[i].last_activity_ms = now;
            alya_vpn_stats_add_rx((uint32_t)n);
            int on = socks5_udp_build(obuf, sizeof(obuf), s_direct_udp[i].target_host,
                                      s_direct_udp[i].target_port, dbuf, n);
            if (on > 0) {
                sendto((SOCKET)s_udp_relay_sock, (const char *)obuf, on, 0,
                       (struct sockaddr *)&s_direct_udp[i].app_src, sizeof(s_direct_udp[i].app_src));
            }
        } else if (n < 0 && !is_would_block()) {
            close_sock(s_direct_udp[i].udp_sock);
            memset(&s_direct_udp[i], 0, sizeof(s_direct_udp[i]));
        }
    }

    // 5. Expire idle tunneled mappings
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_client_udp[i].in_use && now - s_client_udp[i].last_activity_ms > idle_ms) {
            memset(&s_client_udp[i], 0, sizeof(s_client_udp[i]));
        }
    }

    return activity;
}

// Deliver one inbound UDP_DATA payload to the application via the relay.
static int client_udp_deliver(uint32_t assoc_id, const uint8_t *pl, uint32_t plen) {
    if (s_udp_relay_sock < 0) return -1;
    char host[256]; int port = 0;
    const uint8_t *dg = NULL; int dglen = 0;
    if (udp_payload_decode(pl, plen, host, sizeof(host), &port, &dg, &dglen) != 0) return -1;
    AlyaClientUdpEntry *e = NULL;
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_client_udp[i].in_use && s_client_udp[i].assoc_id == assoc_id &&
            s_client_udp[i].target_port == port && strcmp(s_client_udp[i].target_host, host) == 0) {
            e = &s_client_udp[i];
            break;
        }
    }
    if (!e) return -1;
    static uint8_t obuf[65535];
    int on = socks5_udp_build(obuf, sizeof(obuf), host, port, dg, dglen);
    if (on < 0) return -1;
    e->last_activity_ms = get_time_ms();
    alya_vpn_stats_add_rx((uint32_t)dglen);
    return sendto((SOCKET)s_udp_relay_sock, (const char *)obuf, on, 0,
                  (struct sockaddr *)&e->app_src, sizeof(e->app_src));
}

// ============================================================================
// Server-side UDP associations (per client thread)
// ============================================================================

typedef struct {
    int in_use;
    uint32_t assoc_id;
    uint32_t last_activity_ms;
} AlyaSrvUdpAssoc;

typedef struct {
    int in_use;
    uint32_t assoc_id;
    char target_host[256];
    int target_port;
    int udp_sock; // connected UDP socket to the target
    uint32_t last_activity_ms;
} AlyaSrvUdpEntry;

static ALYA_THREAD_LOCAL AlyaSrvUdpAssoc s_srv_udp_assocs[ALYA_MAX_ASSOC];
static ALYA_THREAD_LOCAL AlyaSrvUdpEntry s_srv_udp[ALYA_MAX_UDP_CH];

static AlyaSrvUdpAssoc *srv_udp_assoc_find(uint32_t id) {
    for (int i = 0; i < ALYA_MAX_ASSOC; ++i) {
        if (s_srv_udp_assocs[i].in_use && s_srv_udp_assocs[i].assoc_id == id) return &s_srv_udp_assocs[i];
    }
    return NULL;
}

static void srv_udp_remove_assoc(uint32_t assoc_id) {
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_srv_udp[i].in_use && s_srv_udp[i].assoc_id == assoc_id) {
            close_sock(s_srv_udp[i].udp_sock);
            memset(&s_srv_udp[i], 0, sizeof(s_srv_udp[i]));
        }
    }
    AlyaSrvUdpAssoc *a = srv_udp_assoc_find(assoc_id);
    if (a) memset(a, 0, sizeof(*a));
}

void alya_vpn_srv_udp_clear(void) {
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_srv_udp[i].in_use && s_srv_udp[i].udp_sock >= 0) close_sock(s_srv_udp[i].udp_sock);
    }
    memset(s_srv_udp, 0, sizeof(s_srv_udp));
    memset(s_srv_udp_assocs, 0, sizeof(s_srv_udp_assocs));
}

void alya_vpn_srv_udp_close_all(void) {
    alya_vpn_srv_udp_clear();
}

static AlyaSrvUdpEntry *srv_udp_find_or_create(uint32_t assoc_id, const char *host, int port) {
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (s_srv_udp[i].in_use && s_srv_udp[i].assoc_id == assoc_id &&
            s_srv_udp[i].target_port == port && strcmp(s_srv_udp[i].target_host, host) == 0) {
            s_srv_udp[i].last_activity_ms = get_time_ms();
            return &s_srv_udp[i];
        }
    }
    int s = connect_udp_target(host, port);
    if (s < 0) return NULL;
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (!s_srv_udp[i].in_use) {
            s_srv_udp[i].in_use = 1;
            s_srv_udp[i].assoc_id = assoc_id;
            strncpy(s_srv_udp[i].target_host, host, sizeof(s_srv_udp[i].target_host) - 1);
            s_srv_udp[i].target_port = port;
            s_srv_udp[i].udp_sock = s;
            s_srv_udp[i].last_activity_ms = get_time_ms();
            return &s_srv_udp[i];
        }
    }
    close_sock(s);
    return NULL;
}

// Polls server UDP sockets and forwards replies to the client.
// Called from alya_vpn_pump_server_vpn (sole reader/writer of client_sock).
static int pump_server_udp_sockets(int client_sock) {
    int activity = 0;
    uint32_t now = get_time_ms();
    uint32_t idle_ms = udp_effective_idle_ms();
    static ALYA_THREAD_LOCAL uint8_t dgbuf[65535];
    static ALYA_THREAD_LOCAL uint8_t txbuf[ALYA_AV02_HEADER_LEN + 32768];
    for (int i = 0; i < ALYA_MAX_UDP_CH; ++i) {
        if (!s_srv_udp[i].in_use) continue;
        if (now - s_srv_udp[i].last_activity_ms > idle_ms) {
            close_sock(s_srv_udp[i].udp_sock);
            memset(&s_srv_udp[i], 0, sizeof(s_srv_udp[i]));
            continue;
        }
        int n = recv((SOCKET)s_srv_udp[i].udp_sock, (char *)dgbuf, sizeof(dgbuf), 0);
        if (n > 0) {
            activity = 1;
            s_srv_udp[i].last_activity_ms = now;
            uint8_t *pl = txbuf + ALYA_AV02_HEADER_LEN;
            int plw = udp_payload_encode(pl, (int)sizeof(txbuf) - ALYA_AV02_HEADER_LEN,
                                         s_srv_udp[i].target_host, s_srv_udp[i].target_port,
                                         dgbuf, n);
            if (plw > 0) {
                int flen = alya_vpn_pack_frame_av02(ALYA_AV02_MSG_UDP_DATA, s_srv_udp[i].assoc_id,
                                                    pl, (uint32_t)plw, txbuf, sizeof(txbuf));
                if (flen > 0) send_all(client_sock, txbuf, flen);
            }
        } else if (n < 0 && !is_would_block()) {
            close_sock(s_srv_udp[i].udp_sock);
            memset(&s_srv_udp[i], 0, sizeof(s_srv_udp[i]));
        }
    }
    return activity;
}

// Server-side policy check shared by TCP and UDP CONNECT paths.
// Returns 1 (allow), 0 (deny with response). Deny reasons are logged by callers.
static int server_target_allowed(const char *target, int port, int is_udp) {
    if (is_udp ? !fwd_allows_udp() : !fwd_allows_tcp()) return 0;
    if (alya_vpn_server_is_port_blocked(port)) return 0;
    if (s_srv_block_lan && (is_lan_target(target) ||
             strcmp(target, "127.0.0.1") == 0 || strcmp(target, "localhost") == 0 ||
             strcmp(target, "::1") == 0 || strcmp(target, "0.0.0.0") == 0 ||
             strncmp(target, "169.254.", 8) == 0 || strncmp(target, "10.", 3) == 0 ||
             strncmp(target, "192.168.", 8) == 0 || strncmp(target, "172.", 4) == 0)) return 0;
    return 1;
}

// Server Channel Table
void alya_vpn_srv_ch_set(int channel_id, int dest_sock) {
    set_sock_nonblocking(dest_sock);
    int free_slot = -1;
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use && s_server_channels[i].channel_id == channel_id) {
            s_server_channels[i].dest_sock = dest_sock;
            s_server_channels[i].last_activity_ms = get_time_ms();
            return;
        }
        if (!s_server_channels[i].in_use && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        s_server_channels[free_slot].in_use = 1;
        s_server_channels[free_slot].channel_id = channel_id;
        s_server_channels[free_slot].dest_sock = dest_sock;
        s_server_channels[free_slot].last_activity_ms = get_time_ms();
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
    s_srv_rx_len = 0;
}

void alya_vpn_srv_close_all(void) {
    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (s_server_channels[i].in_use && s_server_channels[i].dest_sock >= 0) {
            close_sock(s_server_channels[i].dest_sock);
        }
    }
    memset(s_server_channels, 0, sizeof(s_server_channels));
    s_srv_rx_len = 0;
}

int alya_vpn_open_client_channel(int vpn_sock, int channel_id, const char *host, int port, int app_sock) {
    if (vpn_sock < 0 || channel_id <= 0 || !host || app_sock < 0) {
        return -1;
    }
    if (!fwd_allows_tcp()) return -2; // TCP forwarding disabled by protocol mode
    set_sock_nonblocking(app_sock);
    set_sock_nonblocking(vpn_sock);
    apply_socket_nodelay(app_sock);
    apply_socket_nodelay(vpn_sock);
    alya_vpn_ch_set(channel_id, app_sock);

    char target[512];
    snprintf(target, sizeof(target), "%s:%d", host, port);
    uint32_t tlen = (uint32_t)strlen(target);

    uint8_t frame_buf[ALYA_AV02_HEADER_LEN + 512];
    int flen = alya_vpn_pack_frame_av02(
        ALYA_AV02_MSG_CONNECT_REQ,
        (uint32_t)channel_id,
        (const uint8_t *)target,
        tlen,
        frame_buf,
        sizeof(frame_buf)
    );
    if (flen <= 0) {
        return -1;
    }

    if (send_all(vpn_sock, frame_buf, flen) != flen) {
        return -1;
    }
    return 0;
}

int alya_vpn_send_ping(int sock, int ch_id) {
    if (sock < 0) return -1;
    uint8_t frame_buf[ALYA_AV02_HEADER_LEN + 16];
    int flen = alya_vpn_pack_frame_av02(
        ALYA_AV02_MSG_PING,
        (uint32_t)ch_id,
        NULL,
        0,
        frame_buf,
        sizeof(frame_buf)
    );
    if (flen > 0) {
        return send_all(sock, frame_buf, flen) == flen ? 0 : -1;
    }
    return -1;
}

int64_t alya_vpn_pump_client_vpn(int vpn_sock) {
    if (vpn_sock < 0) return -1;
    set_sock_nonblocking(vpn_sock);
    int activity = 0;
    uint32_t now_client = get_time_ms();

    // Arka plan keep-alive ping (NAT tablosunun düşmesini önler)
    static uint32_t s_last_ping_ms = 0;
    if (s_ping_interval_ms > 0) {
        if (s_last_ping_ms == 0) s_last_ping_ms = now_client;
        if (now_client - s_last_ping_ms >= (uint32_t)s_ping_interval_ms) {
            s_last_ping_ms = now_client;
            alya_vpn_send_ping(vpn_sock, 0);
        }
    }

    // 1. Read incoming data from vpn_sock
    if (s_vpn_client_rx_len < (int)sizeof(s_vpn_client_rx)) {
        int n = recv((SOCKET)vpn_sock, (char *)(s_vpn_client_rx + s_vpn_client_rx_len),
                     (int)sizeof(s_vpn_client_rx) - s_vpn_client_rx_len, 0);
        if (n > 0) {
            activity = 1;
            s_vpn_client_rx_len += n;
            alya_vpn_stats_add_rx((uint32_t)n);
        } else if (n == 0) {
            s_vpn_client_rx_len = 0;
            return -1; // VPN server disconnected
        } else {
            if (!is_would_block()) {
                s_vpn_client_rx_len = 0;
                return -1;
            }
        }
    }

    // Process complete frames from vpn_sock
    static uint8_t s_client_plain[65536];
    while (s_vpn_client_rx_len >= ALYA_AV02_HEADER_LEN) {
        if (s_vpn_client_rx[0] != ALYA_AV02_MAGIC_0 ||
            s_vpn_client_rx[1] != ALYA_AV02_MAGIC_1 ||
            s_vpn_client_rx[2] != ALYA_AV02_VERSION) {
            memmove(s_vpn_client_rx, s_vpn_client_rx + 1, s_vpn_client_rx_len - 1);
            s_vpn_client_rx_len--;
            continue;
        }

        uint32_t payload_len = ((uint32_t)s_vpn_client_rx[8] << 24) | ((uint32_t)s_vpn_client_rx[9] << 16) |
                               ((uint32_t)s_vpn_client_rx[10] << 8) | (uint32_t)s_vpn_client_rx[11];

        if (payload_len > 65536) {
            memmove(s_vpn_client_rx, s_vpn_client_rx + 1, s_vpn_client_rx_len - 1);
            s_vpn_client_rx_len--;
            continue;
        }

        int total_frame_len = (int)(ALYA_AV02_HEADER_LEN + payload_len);
        if (s_vpn_client_rx_len < total_frame_len) {
            break; // Wait for full frame
        }

        uint8_t out_type = 0;
        uint32_t out_ch = 0;
        uint32_t out_plen = 0;
        int res = alya_vpn_unpack_frame_av02(
            s_vpn_client_rx,
            total_frame_len,
            &out_type,
            &out_ch,
            s_client_plain,
            sizeof(s_client_plain),
            &out_plen
        );

        if (res == 0) {
            activity = 1;
            if (out_type == ALYA_AV02_MSG_DATA) {
                int app_sock = alya_vpn_ch_get((int)out_ch);
                if (app_sock >= 0 && out_plen > 0) {
                    send_all(app_sock, s_client_plain, (int)out_plen);
                    for (int k = 0; k < ALYA_MAX_CHANNELS; ++k) {
                        if (s_client_channels[k].in_use && s_client_channels[k].channel_id == (int)out_ch) {
                            s_client_channels[k].last_activity_ms = now_client;
                            break;
                        }
                    }
                }
            } else if (out_type == ALYA_AV02_MSG_CLOSE) {
                int app_sock = alya_vpn_ch_get((int)out_ch);
                if (app_sock >= 0) {
                    close_sock(app_sock);
                    alya_vpn_ch_remove((int)out_ch);
                }
                assoc_remove(out_ch); // also tears down a UDP association with this id
            } else if (out_type == ALYA_AV02_MSG_CONNECT_RESP) {
                if (out_plen > 0 && s_client_plain[0] != 0) {
                    int app_sock = alya_vpn_ch_get((int)out_ch);
                    if (app_sock >= 0) {
                        close_sock(app_sock);
                        alya_vpn_ch_remove((int)out_ch);
                    }
                    assoc_remove(out_ch); // refused UDP association
                }
            } else if (out_type == ALYA_AV02_MSG_UDP_DATA) {
                if (out_plen > 0) client_udp_deliver(out_ch, s_client_plain, out_plen);
            } else if (out_type == ALYA_AV02_MSG_PONG) {
                // Keep-alive heartbeat pong received
            }
        }

        memmove(s_vpn_client_rx, s_vpn_client_rx + total_frame_len, s_vpn_client_rx_len - total_frame_len);
        s_vpn_client_rx_len -= total_frame_len;
    }

    // 2. Read from active app sockets -> encrypt into AV02 and send to vpn_sock
    static uint8_t s_app_read[32768];
    static uint8_t s_vpn_tx_frame[ALYA_AV02_HEADER_LEN + 32768];

    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (!s_client_channels[i].in_use) continue;
        int ch_id = s_client_channels[i].channel_id;
        int app_sock = s_client_channels[i].app_sock;
        if (app_sock < 0) continue;

        // Channel idle timeout check
        if (s_idle_timeout_ms > 0 && (now_client - s_client_channels[i].last_activity_ms > (uint32_t)s_idle_timeout_ms)) {
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_CLOSE,
                (uint32_t)ch_id,
                NULL,
                0,
                s_vpn_tx_frame,
                sizeof(s_vpn_tx_frame)
            );
            if (flen > 0) {
                if (send_all(vpn_sock, s_vpn_tx_frame, flen) < 0) {
                    return -1;
                }
            }
            close_sock(app_sock);
            s_client_channels[i].in_use = 0;
            s_client_channels[i].app_sock = -1;
            s_client_channels[i].channel_id = 0;
            continue;
        }

        int n = recv((SOCKET)app_sock, (char *)s_app_read, sizeof(s_app_read), 0);
        if (n > 0) {
            activity = 1;
            s_client_channels[i].last_activity_ms = now_client;
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_DATA,
                (uint32_t)ch_id,
                s_app_read,
                (uint32_t)n,
                s_vpn_tx_frame,
                sizeof(s_vpn_tx_frame)
            );
            if (flen > 0) {
                if (send_all(vpn_sock, s_vpn_tx_frame, flen) < 0) {
                    return -1;
                }
            }
        } else if (n == 0) {
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_CLOSE,
                (uint32_t)ch_id,
                NULL,
                0,
                s_vpn_tx_frame,
                sizeof(s_vpn_tx_frame)
            );
            if (flen > 0) {
                if (send_all(vpn_sock, s_vpn_tx_frame, flen) < 0) {
                    return -1;
                }
            }
            close_sock(app_sock);
            s_client_channels[i].in_use = 0;
            s_client_channels[i].app_sock = -1;
            s_client_channels[i].channel_id = 0;
        } else {
            if (!is_would_block()) {
                int flen = alya_vpn_pack_frame_av02(
                    ALYA_AV02_MSG_CLOSE,
                    (uint32_t)ch_id,
                    NULL,
                    0,
                    s_vpn_tx_frame,
                    sizeof(s_vpn_tx_frame)
                );
                if (flen > 0) {
                    if (send_all(vpn_sock, s_vpn_tx_frame, flen) < 0) {
                        return -1;
                    }
                }
                close_sock(app_sock);
                s_client_channels[i].in_use = 0;
                s_client_channels[i].app_sock = -1;
                s_client_channels[i].channel_id = 0;
            }
        }
    }

    return activity;
}

int64_t alya_vpn_pump_server_vpn(int client_sock) {
    if (client_sock < 0) return -1;
    set_sock_nonblocking(client_sock);
    int activity = 0;

    // 1. Read incoming data from client_sock
    if (s_srv_rx_len < (int)sizeof(s_srv_rx)) {
        int n = recv((SOCKET)client_sock, (char *)(s_srv_rx + s_srv_rx_len),
                     (int)sizeof(s_srv_rx) - s_srv_rx_len, 0);
        if (n > 0) {
            activity = 1;
            s_srv_rx_len += n;
        } else if (n == 0) {
            s_srv_rx_len = 0;
            return -1; // Client disconnected
        } else {
            if (!is_would_block()) {
                s_srv_rx_len = 0;
                return -1;
            }
        }
    }

    // Process complete frames from client_sock
    static ALYA_THREAD_LOCAL uint8_t s_srv_plain[65536];
    static ALYA_THREAD_LOCAL uint8_t s_srv_tx_frame[ALYA_AV02_HEADER_LEN + 32768];

    while (s_srv_rx_len >= ALYA_AV02_HEADER_LEN) {
        if (s_srv_rx[0] != ALYA_AV02_MAGIC_0 ||
            s_srv_rx[1] != ALYA_AV02_MAGIC_1 ||
            s_srv_rx[2] != ALYA_AV02_VERSION) {
            memmove(s_srv_rx, s_srv_rx + 1, s_srv_rx_len - 1);
            s_srv_rx_len--;
            continue;
        }

        uint32_t payload_len = ((uint32_t)s_srv_rx[8] << 24) | ((uint32_t)s_srv_rx[9] << 16) |
                               ((uint32_t)s_srv_rx[10] << 8) | (uint32_t)s_srv_rx[11];

        if (payload_len > 65536) {
            memmove(s_srv_rx, s_srv_rx + 1, s_srv_rx_len - 1);
            s_srv_rx_len--;
            continue;
        }

        int total_frame_len = (int)(ALYA_AV02_HEADER_LEN + payload_len);
        if (s_srv_rx_len < total_frame_len) {
            break;
        }

        uint8_t out_type = 0;
        uint32_t out_ch = 0;
        uint32_t out_plen = 0;
        int res = alya_vpn_unpack_frame_av02(
            s_srv_rx,
            total_frame_len,
            &out_type,
            &out_ch,
            s_srv_plain,
            sizeof(s_srv_plain),
            &out_plen
        );

        if (res == 0) {
            activity = 1;
            if (out_type == ALYA_AV02_MSG_DATA) {
                int dest_sock = alya_vpn_srv_ch_get((int)out_ch);
                if (dest_sock >= 0 && out_plen > 0) {
                    send_all(dest_sock, s_srv_plain, (int)out_plen);
                    for (int k = 0; k < ALYA_MAX_CHANNELS; ++k) {
                        if (s_server_channels[k].in_use && s_server_channels[k].channel_id == (int)out_ch) {
                            s_server_channels[k].last_activity_ms = get_time_ms();
                            break;
                        }
                    }
                }
            } else if (out_type == ALYA_AV02_MSG_CONNECT_REQ) {
                if (out_plen < sizeof(s_srv_plain)) {
                    s_srv_plain[out_plen] = '\0';
                } else {
                    s_srv_plain[sizeof(s_srv_plain) - 1] = '\0';
                }
                char *target = (char *)s_srv_plain;
                char *colon = strrchr(target, ':');
                int ok = 0;
                if (colon) {
                    *colon = '\0';
                    int port = atoi(colon + 1);

                    if (!fwd_allows_tcp()) {
                        if (s_srv_log_connections) {
                            printf("[PROTO] Refused TCP connection (protocol mode forbids TCP): Channel %u -> %s:%d\n", out_ch, target, port);
                            fflush(stdout);
                        }
                    }
                    // 1. Security Check: Restricted / Blocked Ports (e.g. SMTP 25, 465, 587 anti-spam)
                    else if (alya_vpn_server_is_port_blocked(port)) {
                        if (s_srv_log_connections) {
                            printf("[SECURITY] Blocked connection to restricted port %d: Channel %u -> %s:%d\n", port, out_ch, target, port);
                            fflush(stdout);
                        }
                    }
                    // 2. Security Check: SSRF protection (Block private LAN, loopback, and cloud metadata)
                    else if (!server_target_allowed(target, port, 0)) {
                        if (s_srv_log_connections) {
                            printf("[SECURITY] Blocked SSRF connection to private LAN destination: Channel %u -> %s:%d\n", out_ch, target, port);
                            fflush(stdout);
                        }
                    } else {
                        int dest_sock = connect_target(target, port);
                        if (dest_sock >= 0) {
                            set_sock_nonblocking(dest_sock);
                            apply_socket_nodelay(dest_sock);
                            alya_vpn_srv_ch_set((int)out_ch, dest_sock);
                            ok = 1;
                            if (s_srv_log_connections) {
                                printf("[FORWARD] Connected: Channel %u -> %s:%d\n", out_ch, target, port);
                                fflush(stdout);
                            }
                        } else {
                            if (s_srv_log_connections) {
                                printf("[FORWARD] Failed to connect: Channel %u -> %s:%d\n", out_ch, target, port);
                                fflush(stdout);
                            }
                        }
                    }
                }
                uint8_t status_byte = ok ? 0 : 1;
                int rlen = alya_vpn_pack_frame_av02(
                    ALYA_AV02_MSG_CONNECT_RESP,
                    out_ch,
                    &status_byte,
                    1,
                    s_srv_tx_frame,
                    sizeof(s_srv_tx_frame)
                );
                if (rlen > 0) {
                    if (send_all(client_sock, s_srv_tx_frame, rlen) < 0) {
                        return -1;
                    }
                }
            } else if (out_type == ALYA_AV02_MSG_CLOSE) {
                int dest_sock = alya_vpn_srv_ch_get((int)out_ch);
                if (dest_sock >= 0) {
                    close_sock(dest_sock);
                    alya_vpn_srv_ch_remove((int)out_ch);
                }
                srv_udp_remove_assoc(out_ch); // also tears down a UDP association
            } else if (out_type == ALYA_AV02_MSG_UDP_ASSOC_REQ) {
                uint8_t status_byte = 1;
                if (fwd_allows_udp()) {
                    int slot = -1;
                    for (int k = 0; k < ALYA_MAX_ASSOC; ++k) {
                        if (!s_srv_udp_assocs[k].in_use) { slot = k; break; }
                    }
                    if (slot >= 0) {
                        s_srv_udp_assocs[slot].in_use = 1;
                        s_srv_udp_assocs[slot].assoc_id = out_ch;
                        s_srv_udp_assocs[slot].last_activity_ms = get_time_ms();
                        status_byte = 0;
                        if (s_srv_log_connections) {
                            printf("[FORWARD] UDP association opened: Assoc %u\n", out_ch);
                            fflush(stdout);
                        }
                    }
                } else if (s_srv_log_connections) {
                    printf("[PROTO] Refused UDP association (protocol mode forbids UDP): Assoc %u\n", out_ch);
                    fflush(stdout);
                }
                int rlen = alya_vpn_pack_frame_av02(ALYA_AV02_MSG_CONNECT_RESP, out_ch,
                                                    &status_byte, 1,
                                                    s_srv_tx_frame, sizeof(s_srv_tx_frame));
                if (rlen > 0 && send_all(client_sock, s_srv_tx_frame, rlen) < 0) return -1;
            } else if (out_type == ALYA_AV02_MSG_UDP_DATA) {
                if (srv_udp_assoc_find(out_ch) && out_plen > 0 && out_plen < sizeof(s_srv_plain)) {
                    char uhost[256]; int uport = 0;
                    const uint8_t *dg = NULL; int dglen = 0;
                    if (udp_payload_decode(s_srv_plain, out_plen, uhost, sizeof(uhost),
                                           &uport, &dg, &dglen) == 0) {
                        if (!server_target_allowed(uhost, uport, 1)) {
                            if (s_srv_log_connections) {
                                printf("[SECURITY] Blocked UDP datagram to disallowed target: Assoc %u -> %s:%d\n", out_ch, uhost, uport);
                                fflush(stdout);
                            }
                        } else {
                            AlyaSrvUdpEntry *ue = srv_udp_find_or_create(out_ch, uhost, uport);
                            if (ue && dglen > 0) {
                                if (send((SOCKET)ue->udp_sock, (const char *)dg, dglen, 0) == dglen) {
                                    ue->last_activity_ms = get_time_ms();
                                }
                            }
                        }
                    }
                    AlyaSrvUdpAssoc *sa = srv_udp_assoc_find(out_ch);
                    if (sa) sa->last_activity_ms = get_time_ms();
                }
            } else if (out_type == ALYA_AV02_MSG_PING) {
                int plen = alya_vpn_pack_frame_av02(
                    ALYA_AV02_MSG_PONG,
                    out_ch,
                    NULL,
                    0,
                    s_srv_tx_frame,
                    sizeof(s_srv_tx_frame)
                );
                if (plen > 0) {
                    if (send_all(client_sock, s_srv_tx_frame, plen) < 0) {
                        return -1;
                    }
                }
            }
        }

        memmove(s_srv_rx, s_srv_rx + total_frame_len, s_srv_rx_len - total_frame_len);
        s_srv_rx_len -= total_frame_len;
    }

    // 2. Poll UDP association sockets -> encapsulate replies & send to client_sock
    if (pump_server_udp_sockets(client_sock)) activity = 1;

    // 3. Read from active destination channels -> encrypt & send to client_sock
    static ALYA_THREAD_LOCAL uint8_t s_dest_read[32768];
    uint32_t now_srv = get_time_ms();

    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (!s_server_channels[i].in_use) continue;
        int ch_id = s_server_channels[i].channel_id;
        int dest_sock = s_server_channels[i].dest_sock;
        if (dest_sock < 0) continue;

        // Channel idle timeout check on server
        if (s_idle_timeout_ms > 0 && (now_srv - s_server_channels[i].last_activity_ms > (uint32_t)s_idle_timeout_ms)) {
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_CLOSE,
                (uint32_t)ch_id,
                NULL,
                0,
                s_srv_tx_frame,
                sizeof(s_srv_tx_frame)
            );
            if (flen > 0) {
                if (send_all(client_sock, s_srv_tx_frame, flen) < 0) {
                    return -1;
                }
            }
            close_sock(dest_sock);
            s_server_channels[i].in_use = 0;
            s_server_channels[i].dest_sock = -1;
            s_server_channels[i].channel_id = 0;
            continue;
        }

        int n = recv((SOCKET)dest_sock, (char *)s_dest_read, sizeof(s_dest_read), 0);
        if (n > 0) {
            activity = 1;
            s_server_channels[i].last_activity_ms = now_srv;
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_DATA,
                (uint32_t)ch_id,
                s_dest_read,
                (uint32_t)n,
                s_srv_tx_frame,
                sizeof(s_srv_tx_frame)
            );
            if (flen > 0) {
                if (send_all(client_sock, s_srv_tx_frame, flen) < 0) {
                    return -1;
                }
            }
        } else if (n == 0) {
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_CLOSE,
                (uint32_t)ch_id,
                NULL,
                0,
                s_srv_tx_frame,
                sizeof(s_srv_tx_frame)
            );
            if (flen > 0) {
                if (send_all(client_sock, s_srv_tx_frame, flen) < 0) {
                    return -1;
                }
            }
            close_sock(dest_sock);
            s_server_channels[i].in_use = 0;
            s_server_channels[i].dest_sock = -1;
            s_server_channels[i].channel_id = 0;
        } else {
            if (!is_would_block()) {
                int flen = alya_vpn_pack_frame_av02(
                    ALYA_AV02_MSG_CLOSE,
                    (uint32_t)ch_id,
                    NULL,
                    0,
                    s_srv_tx_frame,
                    sizeof(s_srv_tx_frame)
                );
                if (flen > 0) {
                    if (send_all(client_sock, s_srv_tx_frame, flen) < 0) {
                        return -1;
                    }
                }
                close_sock(dest_sock);
                s_server_channels[i].in_use = 0;
                s_server_channels[i].dest_sock = -1;
                s_server_channels[i].channel_id = 0;
            }
        }
    }

    return activity;
}

// ============================================================================
// Stop Request & Signal Management (Cross-platform)
// ============================================================================

static volatile int s_stop_requested = 0;
static volatile int s_sig_count = 0;

int alya_vpn_is_stop_requested(void) {
    return s_stop_requested;
}

void alya_vpn_request_stop(void) {
    s_stop_requested = 1;
}

// ============================================================================
// Windows System-Wide Proxy Management
// ============================================================================

#if defined(_WIN32)
static int s_system_proxy_active = 0;

void alya_vpn_set_system_proxy(int enable, int port) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        if (enable) {
            DWORD val_enable = 1;
            char proxy_str[128];
            // Configure HTTP, HTTPS, and SOCKS to point to local proxy port
            snprintf(proxy_str, sizeof(proxy_str), "http=127.0.0.1:%d;https=127.0.0.1:%d;socks=127.0.0.1:%d", port, port, port);

            RegSetValueExA(hKey, "ProxyEnable", 0, REG_DWORD, (const BYTE *)&val_enable, sizeof(val_enable));
            RegSetValueExA(hKey, "ProxyServer", 0, REG_SZ, (const BYTE *)proxy_str, (DWORD)(strlen(proxy_str) + 1));
            RegSetValueExA(hKey, "ProxyOverride", 0, REG_SZ, (const BYTE *)"<local>", 8);
            s_system_proxy_active = 1;
        } else {
            DWORD val_disable = 0;
            RegSetValueExA(hKey, "ProxyEnable", 0, REG_DWORD, (const BYTE *)&val_disable, sizeof(val_disable));
            s_system_proxy_active = 0;
        }
        RegCloseKey(hKey);

        // Notify WinINet and running applications of settings change
        HMODULE hWinINet = LoadLibraryA("wininet.dll");
        if (hWinINet) {
            typedef BOOL (WINAPI *pfnInternetSetOptionA)(HANDLE, DWORD, LPVOID, DWORD);
            pfnInternetSetOptionA pSetOpt = (pfnInternetSetOptionA)GetProcAddress(hWinINet, "InternetSetOptionA");
            if (pSetOpt) {
                pSetOpt(NULL, 39 /* INTERNET_OPTION_SETTINGS_CHANGED */, NULL, 0);
                pSetOpt(NULL, 37 /* INTERNET_OPTION_REFRESH */, NULL, 0);
            }
            FreeLibrary(hWinINet);
        }
    }
}

static void vpn_cleanup_on_exit(void) {
    if (s_system_proxy_active) {
        alya_vpn_set_system_proxy(0, 0);
    }
}

static BOOL WINAPI vpn_console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        s_stop_requested = 1;
        s_sig_count++;
        if (s_sig_count > 1 || ctrl_type == CTRL_CLOSE_EVENT) {
            vpn_cleanup_on_exit();
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

void alya_vpn_init_system_proxy_hook(void) {
    atexit(vpn_cleanup_on_exit);
    SetConsoleCtrlHandler(vpn_console_ctrl_handler, TRUE);
}
#elif defined(__APPLE__)

#define ALYA_MAC_MAX_SERVICES 16

static int s_mac_proxy_active = 0;

// Enumerates enabled network services (Wi-Fi, Ethernet, iPhone USB,
// Thunderbolt Bridge, USB LAN, ...). Hardcoding two names silently skips
// whichever uplink is actually active.
static int macos_list_services(char svcs[][128], int max_svcs) {
    int n = 0;
    FILE *fp = popen("networksetup -listallnetworkservices 2>/dev/null", "r");
    if (!fp) return 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t L = strlen(line);
        while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = '\0';
        if (L == 0 || line[0] == '*') continue; // empty / disabled service
        if (strncmp(line, "An asterisk", 11) == 0) continue; // header note
        if (n < max_svcs) {
            strncpy(svcs[n], line, 127);
            svcs[n][127] = '\0';
            n++;
        }
    }
    pclose(fp);
    return n;
}

// Per-service DNS override bookkeeping. Raw UDP/53 never enters the SOCKS
// proxy, so while the tunnel is active the OS resolvers are pointed at
// uncensored DNS and restored afterwards. SIGKILL skips atexit restore;
// the user must then re-select DNS manually (documented in client.toml).
static char s_mac_dns_svc[ALYA_MAC_MAX_SERVICES][128];
static char s_mac_dns_val[ALYA_MAC_MAX_SERVICES][256];
static int s_mac_dns_count = 0;

// Picks override DNS: user-configured IPv4 literals first, else public pair.
static void macos_dns_pick_override(char *out, int max_out) {
    char picked[2][64];
    int np = 0;
    for (int i = 0; i < s_dns_server_count && np < 2; ++i) {
        unsigned int a, b, c, d;
        if (sscanf(s_dns_servers[i], "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
            a < 256 && b < 256 && c < 256 && d < 256) {
            snprintf(picked[np], sizeof(picked[np]), "%u.%u.%u.%u", a, b, c, d);
            np++;
        }
    }
    if (np == 0) {
        snprintf(out, (size_t)max_out, "1.1.1.1 8.8.8.8");
    } else if (np == 1) {
        snprintf(out, (size_t)max_out, "%s", picked[0]);
    } else {
        snprintf(out, (size_t)max_out, "%s %s", picked[0], picked[1]);
    }
}

static void macos_set_service_dns(const char *service, int enable) {
    char cmd[512];
    if (enable) {
        int known = 0;
        for (int i = 0; i < s_mac_dns_count; ++i) {
            if (strcmp(s_mac_dns_svc[i], service) == 0) { known = 1; break; }
        }
        if (!known && s_mac_dns_count < ALYA_MAC_MAX_SERVICES) {
            char acc[256] = {0};
            snprintf(cmd, sizeof(cmd), "networksetup -getdnsservers \"%s\" 2>/dev/null", service);
            FILE *fp = popen(cmd, "r");
            if (fp) {
                char line[128];
                while (fgets(line, sizeof(line), fp)) {
                    size_t L = strlen(line);
                    while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r' ||
                                     line[L - 1] == ' ' || line[L - 1] == '\t')) line[--L] = '\0';
                    if (L == 0) continue;
                    if (strstr(line, "There aren't any DNS") != NULL) { acc[0] = '\0'; break; }
                    if (strlen(acc) + L + 2 < sizeof(acc)) {
                        if (acc[0]) strncat(acc, " ", sizeof(acc) - strlen(acc) - 1);
                        strncat(acc, line, sizeof(acc) - strlen(acc) - 1);
                    }
                }
                pclose(fp);
            }
            strncpy(s_mac_dns_svc[s_mac_dns_count], service, 127);
            s_mac_dns_svc[s_mac_dns_count][127] = '\0';
            if (acc[0]) {
                strncpy(s_mac_dns_val[s_mac_dns_count], acc, 255);
            } else {
                strncpy(s_mac_dns_val[s_mac_dns_count], "Empty", 255);
            }
            s_mac_dns_val[s_mac_dns_count][255] = '\0';
            s_mac_dns_count++;
        }
        char bypass[128];
        macos_dns_pick_override(bypass, sizeof(bypass));
        snprintf(cmd, sizeof(cmd), "networksetup -setdnsservers \"%s\" %s >/dev/null 2>&1",
                 service, bypass);
        system(cmd);
    } else {
        for (int i = 0; i < s_mac_dns_count; ++i) {
            if (strcmp(s_mac_dns_svc[i], service) == 0) {
                snprintf(cmd, sizeof(cmd), "networksetup -setdnsservers \"%s\" %s >/dev/null 2>&1",
                         service, s_mac_dns_val[i]);
                system(cmd);
                if (i != s_mac_dns_count - 1) {
                    memcpy(s_mac_dns_svc[i], s_mac_dns_svc[s_mac_dns_count - 1],
                           sizeof(s_mac_dns_svc[i]));
                    memcpy(s_mac_dns_val[i], s_mac_dns_val[s_mac_dns_count - 1],
                           sizeof(s_mac_dns_val[i]));
                }
                memset(s_mac_dns_svc[s_mac_dns_count - 1], 0, sizeof(s_mac_dns_svc[0]));
                memset(s_mac_dns_val[s_mac_dns_count - 1], 0, sizeof(s_mac_dns_val[0]));
                s_mac_dns_count--;
                break;
            }
        }
    }
}

static void macos_set_service_proxy(const char *service, int enable, int port) {
    char cmd[256];
    if (enable) {
        snprintf(cmd, sizeof(cmd), "networksetup -setsocksfirewallproxy \"%s\" 127.0.0.1 %d >/dev/null 2>&1", service, port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setsocksfirewallproxystate \"%s\" on >/dev/null 2>&1", service);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setwebproxy \"%s\" 127.0.0.1 %d >/dev/null 2>&1", service, port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setwebproxystate \"%s\" on >/dev/null 2>&1", service);
        snprintf(cmd, sizeof(cmd), "networksetup -setsecurewebproxy \"%s\" 127.0.0.1 %d >/dev/null 2>&1", service, port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setsecurewebproxystate \"%s\" on >/dev/null 2>&1", service);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setproxybypassdomains \"%s\" 127.0.0.1 localhost *.local 169.254/16 >/dev/null 2>&1", service);
        system(cmd);
        system("dscacheutil -flushcache >/dev/null 2>&1");
    } else {
        snprintf(cmd, sizeof(cmd), "networksetup -setsocksfirewallproxystate \"%s\" off >/dev/null 2>&1", service);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setwebproxystate \"%s\" off >/dev/null 2>&1", service);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "networksetup -setsecurewebproxystate \"%s\" off >/dev/null 2>&1", service);
        system(cmd);
        system("dscacheutil -flushcache >/dev/null 2>&1");
    }
}

static void vpn_mac_cleanup_on_exit(void) {
    if (s_mac_proxy_active) {
        alya_vpn_set_system_proxy(0, 0);
    }
}

static void vpn_posix_sig_handler(int sig) {
    (void)sig;
    s_stop_requested = 1;
    s_sig_count++;
    if (s_sig_count > 1) {
        vpn_mac_cleanup_on_exit();
        _exit(0);
    }
}

void alya_vpn_set_system_proxy(int enable, int port) {
    char svcs[ALYA_MAC_MAX_SERVICES][128];
    int n = macos_list_services(svcs, ALYA_MAC_MAX_SERVICES);
    if (n <= 0) {
        // networksetup unavailable: keep the historical pair as fallback.
        strncpy(svcs[0], "Wi-Fi", 127);
        svcs[0][127] = '\0';
        strncpy(svcs[1], "Ethernet", 127);
        svcs[1][127] = '\0';
        n = 2;
    }
    for (int i = 0; i < n; ++i) {
        macos_set_service_proxy(svcs[i], enable, port);
        // Mirror DNS through the tunnel while active; entries are saved
        // above and restored on disable/exit.
        if (s_tunnel_dns) macos_set_service_dns(svcs[i], enable);
    }

    // Resolve active GUI user UID (if running under sudo)
    const char *sudo_uid = getenv("SUDO_UID");
    char uid_buf[32] = "";
    if (sudo_uid && strlen(sudo_uid) > 0) {
        snprintf(uid_buf, sizeof(uid_buf), "%s", sudo_uid);
    } else {
        const char *sudo_user = getenv("SUDO_USER");
        if (sudo_user && strlen(sudo_user) > 0) {
            FILE *fp = popen("id -u \"$SUDO_USER\" 2>/dev/null", "r");
            if (fp) {
                if (fgets(uid_buf, sizeof(uid_buf), fp)) {
                    char *nl = strchr(uid_buf, '\n');
                    if (nl) *nl = '\0';
                }
                pclose(fp);
            }
        }
    }

    char cmd[512];
    if (enable) {
        if (uid_buf[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl setenv http_proxy http://127.0.0.1:%d >/dev/null 2>&1", uid_buf, port);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl setenv https_proxy http://127.0.0.1:%d >/dev/null 2>&1", uid_buf, port);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl setenv all_proxy socks5://127.0.0.1:%d >/dev/null 2>&1", uid_buf, port);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl setenv HTTP_PROXY http://127.0.0.1:%d >/dev/null 2>&1", uid_buf, port);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl setenv HTTPS_PROXY http://127.0.0.1:%d >/dev/null 2>&1", uid_buf, port);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl setenv ALL_PROXY socks5://127.0.0.1:%d >/dev/null 2>&1", uid_buf, port);
            system(cmd);
        }
        snprintf(cmd, sizeof(cmd), "launchctl setenv http_proxy http://127.0.0.1:%d >/dev/null 2>&1", port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "launchctl setenv https_proxy http://127.0.0.1:%d >/dev/null 2>&1", port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "launchctl setenv all_proxy socks5://127.0.0.1:%d >/dev/null 2>&1", port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "launchctl setenv HTTP_PROXY http://127.0.0.1:%d >/dev/null 2>&1", port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "launchctl setenv HTTPS_PROXY http://127.0.0.1:%d >/dev/null 2>&1", port);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "launchctl setenv ALL_PROXY socks5://127.0.0.1:%d >/dev/null 2>&1", port);
        system(cmd);
    } else {
        if (uid_buf[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl unsetenv http_proxy >/dev/null 2>&1", uid_buf);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl unsetenv https_proxy >/dev/null 2>&1", uid_buf);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl unsetenv all_proxy >/dev/null 2>&1", uid_buf);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl unsetenv HTTP_PROXY >/dev/null 2>&1", uid_buf);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl unsetenv HTTPS_PROXY >/dev/null 2>&1", uid_buf);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "launchctl asuser %s launchctl unsetenv ALL_PROXY >/dev/null 2>&1", uid_buf);
            system(cmd);
        }
        system("launchctl unsetenv http_proxy >/dev/null 2>&1");
        system("launchctl unsetenv https_proxy >/dev/null 2>&1");
        system("launchctl unsetenv all_proxy >/dev/null 2>&1");
        system("launchctl unsetenv HTTP_PROXY >/dev/null 2>&1");
        system("launchctl unsetenv HTTPS_PROXY >/dev/null 2>&1");
        system("launchctl unsetenv ALL_PROXY >/dev/null 2>&1");
    }

    s_mac_proxy_active = enable ? 1 : 0;
}

void alya_vpn_init_system_proxy_hook(void) {
    signal(SIGPIPE, SIG_IGN);
    atexit(vpn_mac_cleanup_on_exit);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = vpn_posix_sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

#elif defined(__linux__)

static int s_linux_proxy_active = 0;

static void vpn_linux_cleanup_on_exit(void) {
    if (s_linux_proxy_active) {
        alya_vpn_set_system_proxy(0, 0);
    }
}

static void vpn_posix_sig_handler(int sig) {
    (void)sig;
    s_stop_requested = 1;
    s_sig_count++;
    if (s_sig_count > 1) {
        vpn_linux_cleanup_on_exit();
        _exit(0);
    }
}

void alya_vpn_set_system_proxy(int enable, int port) {
    if (enable) {
        char cmd[256];
        // GNOME / Ubuntu / Debian desktop proxy
        system("gsettings set org.gnome.system.proxy mode 'manual' >/dev/null 2>&1");
        system("gsettings set org.gnome.system.proxy.socks host '127.0.0.1' >/dev/null 2>&1");
        snprintf(cmd, sizeof(cmd), "gsettings set org.gnome.system.proxy.socks port %d >/dev/null 2>&1", port);
        system(cmd);
        system("gsettings set org.gnome.system.proxy.http host '127.0.0.1' >/dev/null 2>&1");
        snprintf(cmd, sizeof(cmd), "gsettings set org.gnome.system.proxy.http port %d >/dev/null 2>&1", port);
        system(cmd);
        system("gsettings set org.gnome.system.proxy.https host '127.0.0.1' >/dev/null 2>&1");
        snprintf(cmd, sizeof(cmd), "gsettings set org.gnome.system.proxy.https port %d >/dev/null 2>&1", port);
        system(cmd);

        s_linux_proxy_active = 1;
    } else {
        system("gsettings set org.gnome.system.proxy mode 'none' >/dev/null 2>&1");
        s_linux_proxy_active = 0;
    }
}

void alya_vpn_init_system_proxy_hook(void) {
    signal(SIGPIPE, SIG_IGN);
    atexit(vpn_linux_cleanup_on_exit);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = vpn_posix_sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

#else

void alya_vpn_set_system_proxy(int enable, int port) {
    (void)enable; (void)port;
}
void alya_vpn_init_system_proxy_hook(void) {}

#endif