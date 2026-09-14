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

    // Fast fallback using lsof for short-lived or race sockets
    if (!found && peer_remote_port > 0) {
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
    for (int i = 0; i < num_pids && !found; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;

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
    return alya_vpn_get_process_by_port(local_port, out_name, max_len);
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

    // 1. Initial Greeting / Request peek
    unsigned char greet[1024];
    int n = recv((SOCKET)client_sock, (char *)greet, sizeof(greet) - 1, 0);
    if (n < 2) {
        return -1;
    }
    greet[n] = '\0';

    // Protocol A: SOCKS5 [0x05, NMETHODS, METHODS...]
    if (greet[0] == 0x05) {
        const unsigned char greet_resp[2] = {0x05, 0x00};
        if (send((SOCKET)client_sock, (const char *)greet_resp, 2, 0) != 2) {
            return -1;
        }

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

        // Read remaining headers until \r\n\r\n if needed
        if (strstr(space + 1, "\r\n\r\n") == NULL) {
            char extra[512];
            while (1) {
                int en = recv((SOCKET)client_sock, extra, sizeof(extra) - 1, 0);
                if (en <= 0) break;
                extra[en] = '\0';
                if (strstr(extra, "\r\n\r\n") != NULL) break;
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

// UPDATED: Now takes both proxy_local_port (the port the VPN proxy listens on)
// and peer_remote_port (the client's ephemeral source port).
// Uses the new alya_vpn_get_process_by_peer_port which matches BOTH ports.
int alya_vpn_check_peer_route(int proxy_local_port, int peer_remote_port, char *out_proc_name, int max_len) {
    if (!out_proc_name || max_len <= 0) return 1;
    out_proc_name[0] = '\0';
    int res = alya_vpn_get_process_by_peer_port(proxy_local_port, peer_remote_port, out_proc_name, max_len);
    if (!res || !out_proc_name[0]) {
        strncpy(out_proc_name, "unknown", (size_t)max_len - 1);
        out_proc_name[max_len - 1] = '\0';
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
} AlyaChannelEntry;

typedef struct {
    int in_use;
    int connecting;
    uint32_t connect_start_ms;
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

static uint32_t get_time_ms(void) {
#if defined(_WIN32)
    return (uint32_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
#endif
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

static int is_would_block(void) {
#if defined(_WIN32)
    int err = WSAGetLastError();
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
#if defined(_WIN32)
        DWORD tv = 3000;
        setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif

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
            if (now - s_client_directs[i].connect_start_ms > 4000) {
                // Timeout after 4 seconds
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

        // 1. App -> Destination (uploading request / data / photos)
        int n1 = recv((SOCKET)a_sock, buf, sizeof(buf), 0);
        if (n1 > 0) {
            activity = 1;
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

// Server Channel Table
void alya_vpn_srv_ch_set(int channel_id, int dest_sock) {
    set_sock_nonblocking(dest_sock);
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
    set_sock_nonblocking(app_sock);
    set_sock_nonblocking(vpn_sock);
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

int alya_vpn_pump_client_vpn(int vpn_sock) {
    if (vpn_sock < 0) return -1;
    set_sock_nonblocking(vpn_sock);
    int activity = 0;

    // 1. Read incoming data from vpn_sock
    if (s_vpn_client_rx_len < (int)sizeof(s_vpn_client_rx)) {
        int n = recv((SOCKET)vpn_sock, (char *)(s_vpn_client_rx + s_vpn_client_rx_len),
                     (int)sizeof(s_vpn_client_rx) - s_vpn_client_rx_len, 0);
        if (n > 0) {
            activity = 1;
            s_vpn_client_rx_len += n;
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
                }
            } else if (out_type == ALYA_AV02_MSG_CLOSE) {
                int app_sock = alya_vpn_ch_get((int)out_ch);
                if (app_sock >= 0) {
                    close_sock(app_sock);
                    alya_vpn_ch_remove((int)out_ch);
                }
            } else if (out_type == ALYA_AV02_MSG_CONNECT_RESP) {
                if (out_plen > 0 && s_client_plain[0] != 0) {
                    int app_sock = alya_vpn_ch_get((int)out_ch);
                    if (app_sock >= 0) {
                        close_sock(app_sock);
                        alya_vpn_ch_remove((int)out_ch);
                    }
                }
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

        int n = recv((SOCKET)app_sock, (char *)s_app_read, sizeof(s_app_read), 0);
        if (n > 0) {
            activity = 1;
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_DATA,
                (uint32_t)ch_id,
                s_app_read,
                (uint32_t)n,
                s_vpn_tx_frame,
                sizeof(s_vpn_tx_frame)
            );
            if (flen > 0) {
                send_all(vpn_sock, s_vpn_tx_frame, flen);
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
                send_all(vpn_sock, s_vpn_tx_frame, flen);
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
                    send_all(vpn_sock, s_vpn_tx_frame, flen);
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

int alya_vpn_pump_server_vpn(int client_sock) {
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
                    int dest_sock = connect_target(target, port);
                    if (dest_sock >= 0) {
                        set_sock_nonblocking(dest_sock);
                        alya_vpn_srv_ch_set((int)out_ch, dest_sock);
                        ok = 1;
                        printf("[FORWARD] Connected: Channel %u -> %s:%d\n", out_ch, target, port);
                        fflush(stdout);
                    } else {
                        printf("[FORWARD] Failed to connect: Channel %u -> %s:%d\n", out_ch, target, port);
                        fflush(stdout);
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
                    send_all(client_sock, s_srv_tx_frame, rlen);
                }
            } else if (out_type == ALYA_AV02_MSG_CLOSE) {
                int dest_sock = alya_vpn_srv_ch_get((int)out_ch);
                if (dest_sock >= 0) {
                    close_sock(dest_sock);
                    alya_vpn_srv_ch_remove((int)out_ch);
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
                    send_all(client_sock, s_srv_tx_frame, plen);
                }
            }
        }

        memmove(s_srv_rx, s_srv_rx + total_frame_len, s_srv_rx_len - total_frame_len);
        s_srv_rx_len -= total_frame_len;
    }

    // 2. Read from active destination channels -> encrypt & send to client_sock
    static ALYA_THREAD_LOCAL uint8_t s_dest_read[32768];

    for (int i = 0; i < ALYA_MAX_CHANNELS; ++i) {
        if (!s_server_channels[i].in_use) continue;
        int ch_id = s_server_channels[i].channel_id;
        int dest_sock = s_server_channels[i].dest_sock;
        if (dest_sock < 0) continue;

        int n = recv((SOCKET)dest_sock, (char *)s_dest_read, sizeof(s_dest_read), 0);
        if (n > 0) {
            activity = 1;
            int flen = alya_vpn_pack_frame_av02(
                ALYA_AV02_MSG_DATA,
                (uint32_t)ch_id,
                s_dest_read,
                (uint32_t)n,
                s_srv_tx_frame,
                sizeof(s_srv_tx_frame)
            );
            if (flen > 0) {
                send_all(client_sock, s_srv_tx_frame, flen);
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
                send_all(client_sock, s_srv_tx_frame, flen);
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
                    send_all(client_sock, s_srv_tx_frame, flen);
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

static int s_mac_proxy_active = 0;

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
    macos_set_service_proxy("Wi-Fi", enable, port);
    macos_set_service_proxy("Ethernet", enable, port);

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