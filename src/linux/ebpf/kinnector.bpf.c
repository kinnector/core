#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Data structures — must match C++ TelemetryEvent and Rust TelemetryEventRaw
// ---------------------------------------------------------------------------

struct process_key {
    uint32_t pid;
    uint64_t start_time;
};

struct TelemetryHeader {
    uint64_t sequence_number;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint8_t  event_type;
    uint8_t  source;
} __attribute__((packed));

struct ProcessCreateDetails {
    uint32_t child_pid;
    uint32_t real_parent_pid;
    char child_image_path[512];
    char child_command_line[1024];
} __attribute__((packed));

struct FileReadDetails {
    uint32_t bytes_requested;
    int32_t  zone_id;
    char file_path[512];
} __attribute__((packed));

struct FileWriteDetails {
    uint32_t bytes_written;
    int32_t  zone_id;
    char file_path[512];
} __attribute__((packed));

struct NetworkConnectDetails {
    char     destination_ip[46];
    uint16_t destination_port;
    char     protocol[8];
} __attribute__((packed));

struct MemoryMapDetails {
    uint64_t addr;
    uint64_t length;
    uint32_t prot;          // PROT_READ | PROT_WRITE | PROT_EXEC
    uint32_t flags;         // MAP_ANONYMOUS | MAP_PRIVATE etc.
    int32_t  fd;            // -1 for anonymous
    uint64_t file_inode;    // Fix 6: inode of backing file (0 for anonymous regions)
} __attribute__((packed));

struct Dup2Details {
    uint32_t oldfd;
    uint32_t newfd;         // 0=stdin, 1=stdout, 2=stderr (reverse shell indicator)
} __attribute__((packed));

// Fix 8/11: PtraceAttach telemetry struct.
// Emitted on every lsm/ptrace_access_check regardless of trust level,
// so the agent can correlate injection attempts on high-value targets.
struct PtraceAttachDetails {
    uint32_t tracee_pid;    // PID of the process being attached to
    uint32_t mode;          // ptrace mode flags (PTRACE_MODE_READ, etc.)
} __attribute__((packed));

// Fix 10: ImageLoadDetails for lsm/mmap_file SO load telemetry.
struct ImageLoadDetails {
    uint64_t file_inode;    // inode of the mapped file
    char     module_path[256]; // dentry name of the loaded module
} __attribute__((packed));

struct ProcessStopDetails {
    uint32_t exit_code;
    uint32_t _pad;
} __attribute__((packed));

struct TelemetryEvent {
    struct TelemetryHeader header;
    union {
        struct ProcessCreateDetails  process_create;
        struct FileReadDetails       file_read;
        struct FileWriteDetails      file_write;
        struct NetworkConnectDetails network_connect;
        struct MemoryMapDetails      memory_map;
        struct Dup2Details           dup2;
        struct ProcessStopDetails    process_stop;
        struct PtraceAttachDetails   ptrace_attach;  // Fix 8/11
        struct ImageLoadDetails      image_load;     // Fix 10
        char   details_buffer[1544];
    } details;
} __attribute__((packed));

// ---------------------------------------------------------------------------
// EventType constants (must match Rust EventType enum)
// ---------------------------------------------------------------------------
#define EVT_PROCESS_CREATE  1
#define EVT_PROCESS_STOP    2
#define EVT_FILE_READ       3
#define EVT_FILE_WRITE      4
#define EVT_MEMORY_MAP      5
#define EVT_NETWORK_CONNECT 7
// Fix 8/11: PtraceAttach matches Rust EventType::PtraceAttach = 13
#define EVT_PTRACE_ATTACH   13
// Fix 10: ImageLoad matches Rust EventType::ImageLoad = 8
#define EVT_IMAGE_LOAD      8
// Fix 6: MemoryProtect matches Rust EventType::MemoryProtect = 12
// (reuse EVT_MEMORY_MAP for the existing anonymous path, add dedicated constant)
#define EVT_MEMORY_PROTECT  12
#define EVT_DUP2            18
#define EVT_LISTEN          19



// TelemetrySource constants
#define SRC_BPF_LSM         6
#define SRC_BPF_TRACEPOINT  7

#ifndef EACCES
#define EACCES 13
#endif

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

// Map: (pid, start_time) -> category bitmask (sensitive file categories opened)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct process_key);
    __type(value, uint32_t);
} category_flags_map SEC(".maps");

// Map: (pid, start_time) -> pending network connect flags (non-zero = active outbound)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct process_key);
    __type(value, uint32_t);
} pending_network_connect SEC(".maps");

// Map: (pid, start_time) -> trusted state (1 = absolutely trusted)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct process_key);
    __type(value, uint8_t);
} trusted_ancestor_roots SEC(".maps");

// Map: Inode -> Category ID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, uint32_t);
} sensitive_inodes_map SEC(".maps");

// Map: Inode -> TrustLevel (2 = Verified, 3 = Naked TTY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, uint32_t);
} trusted_exec_inodes SEC(".maps");

// Map: (pid, start_time) -> threshold (1 = Untrusted, 2 = Verified, 3 = Naked TTY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct process_key);
    __type(value, uint32_t);
} process_threshold_map SEC(".maps");

// Map: Config Key (0 = blocking_enabled) -> Value
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint32_t);
} config_map SEC(".maps");

// Map: (pid, start_time) -> exfiltration taint hops
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct process_key);
    __type(value, uint32_t);
} tainted_process_map SEC(".maps");

// P2-9: Per-CPU atomic sequence counter for event ordering
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} seq_counter SEC(".maps");

// Ring buffer for sending events to kinnect-agent
// P2-12: Increased to 16MB to reduce event loss under high load
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB (was 4MB)
} telemetry_ringbuf SEC(".maps");

struct tty_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t len;
    uint8_t  is_write;
    char     comm[16];
    char     data[1024];
} __attribute__((packed));

struct tty_read_req {
    struct file *file;
    char *buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB
} tty_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t); // thread ID
    __type(value, struct tty_read_req);
} pending_tty_reads SEC(".maps");


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline struct process_key get_current_process_key() {
    struct process_key key = {0};
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&key.start_time, sizeof(key.start_time), &task->start_time);
    }
    return key;
}

// P2-9: Increment and return a monotonic sequence number
static __always_inline uint64_t next_seq() {
    uint32_t idx = 0;
    uint64_t *cnt = bpf_map_lookup_elem(&seq_counter, &idx);
    if (cnt) {
        (*cnt)++;
        return *cnt;
    }
    return 0;
}

// Initialise header fields common to all events
static __always_inline void fill_header(struct TelemetryEvent *ev,
                                        uint8_t event_type, uint8_t source,
                                        uint32_t pid) {
    ev->header.sequence_number = next_seq();
    ev->header.timestamp_ns    = bpf_ktime_get_ns();
    ev->header.pid             = pid;
    ev->header.event_type      = event_type;
    ev->header.source          = source;
}

// ---------------------------------------------------------------------------
// BPF LSM Hooks
// ---------------------------------------------------------------------------

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int mask) {
    if (!file)
        return 0;

    struct process_key key = get_current_process_key();

    // Check if the process is absolutely trusted
    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    uint64_t ino = BPF_CORE_READ(inode, i_ino);

    // 1. Procfs, input device and uinput protection (synchronous vetoes)
    if (blocking_enabled) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char filename[32] = {0};
            bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

            struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
            char parent_name[32] = {0};
            if (parent) {
                struct qstr p_name = BPF_CORE_READ(parent, d_name);
                bpf_probe_read_kernel_str(parent_name, sizeof(parent_name), p_name.name);
            }

            bool is_blocked_dev = false;
            // Check for /dev/input/event*
            if (parent_name[0] == 'i' && parent_name[1] == 'n' && parent_name[2] == 'p' && parent_name[3] == 'u' && parent_name[4] == 't' && parent_name[5] == '\0') {
                if (filename[0] == 'e' && filename[1] == 'v' && filename[2] == 'e' && filename[3] == 'n' && filename[4] == 't') {
                    is_blocked_dev = true;
                }
            }
            // Check for /dev/uinput
            else if (filename[0] == 'u' && filename[1] == 'i' && filename[2] == 'n' && filename[3] == 'p' && filename[4] == 'u' && filename[5] == 't' && filename[6] == '\0') {
                is_blocked_dev = true;
            }
            // Check for /proc/<pid>/mem (writes only)
            else if (filename[0] == 'm' && filename[1] == 'e' && filename[2] == 'm' && filename[3] == '\0') {
                if (parent_name[0] >= '0' && parent_name[0] <= '9') {
                    if (mask & 0x0002) {
                        is_blocked_dev = true;
                    }
                }
            }

            if (is_blocked_dev) {
                uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
                if (threshold && *threshold == 1) {
                    return -EACCES; // Block synchronously!
                }
            }
        }
    }

    // 2. Sensitive files protection
    uint32_t *category = bpf_map_lookup_elem(&sensitive_inodes_map, &ino);
    if (!category)
        return 0;

    // Check if the process threshold is 1 (Untrusted)
    if (blocking_enabled) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold && *threshold == 1) {
            // Emit blocked event first
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, EVT_FILE_READ, SRC_BPF_LSM, key.pid);
                event->details.file_read.bytes_requested = 0;
                event->details.file_read.zone_id = 0;
                struct qstr d_name;
                bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
                bpf_probe_read_kernel_str(&event->details.file_read.file_path,
                                          sizeof(event->details.file_read.file_path), d_name.name);
                bpf_ringbuf_submit(event, 0);
            }
            return -EACCES; // Block synchronously!
        }
    }

    uint32_t *flags = bpf_map_lookup_elem(&category_flags_map, &key);
    if (flags) {
        uint32_t new_flags = *flags | *category;
        bpf_map_update_elem(&category_flags_map, &key, &new_flags, BPF_ANY);
    } else {
        uint32_t new_flags = *category;
        bpf_map_update_elem(&category_flags_map, &key, &new_flags, BPF_ANY);
    }

    // Emit event to ring buffer for user-space heuristics state tracking
    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_FILE_READ, SRC_BPF_LSM, key.pid);
        event->details.file_read.bytes_requested = 0;
        event->details.file_read.zone_id = 0;
        struct qstr d_name;
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
        bpf_probe_read_kernel_str(&event->details.file_read.file_path,
                                  sizeof(event->details.file_read.file_path), d_name.name);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

// P2-8: lsm/file_permission — emit FileWrite events for web-root write detection (M-13 fix)
SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
#define MAY_WRITE 0x2
    if (!(mask & MAY_WRITE))
        return 0;

    if (!file)
        return 0;

    struct process_key key = get_current_process_key();

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_FILE_WRITE, SRC_BPF_LSM, key.pid);
        event->details.file_write.bytes_written = 0;
        event->details.file_write.zone_id = 0;
        struct qstr d_name;
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
        bpf_probe_read_kernel_str(&event->details.file_write.file_path,
                                  sizeof(event->details.file_write.file_path), d_name.name);
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

// B-07 fix: lsm/socket_connect — extract actual IP from sockaddr_in/in6 (not hardcoded)
SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    unsigned short family = 0;
    if (address) {
        bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    }
    if (family != 1 && family != 2 && family != 10) {
        return 0; // Only intercept Unix (AF_UNIX=1), IPv4 (AF_INET=2) and IPv6 (AF_INET6=10)
    }

    struct process_key key = get_current_process_key();

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    // 1. GUI Display and PipeWire Socket connect protection
    if (family == 1 && blocking_enabled) { // AF_UNIX
        char path[108] = {0};
        bpf_probe_read_kernel_str(path, sizeof(path), (char *)address + 2); // struct sockaddr_un.sun_path

        bool is_gui_socket = false;
        // Check for X11 display socket: /tmp/.X11-unix/X*
        if (path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p' && path[4] == '/' && path[5] == '.' && path[6] == 'X' && path[7] == '1' && path[8] == '1') {
            is_gui_socket = true;
        } else {
            // Check for PipeWire socket: search for "pipewire-0"
            for (int i = 0; i < 90; i++) {
                if (path[i] == 'p' && path[i+1] == 'i' && path[i+2] == 'p' && path[i+3] == 'e' && path[i+4] == 'w' && path[i+5] == 'i' && path[i+6] == 'r' && path[i+7] == 'e') {
                    is_gui_socket = true;
                    break;
                }
            }
        }

        if (is_gui_socket) {
            uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
            if (threshold && *threshold == 1) {
                return -EACCES; // Block connection to display/audio server!
            }
        }
    }

    // Set PendingNetworkConnect flag in maps (for IPv4/IPv6 connections)
    if (family == 2 || family == 10) {
        uint32_t conn_active = 1;
        bpf_map_update_elem(&pending_network_connect, &key, &conn_active, BPF_ANY);
    }

    // 2. Synchronous network blocking for untrusted processes
    if ((family == 2 || family == 10) && blocking_enabled) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold && *threshold == 1) {
            // Emit blocked event first
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, EVT_NETWORK_CONNECT, SRC_BPF_LSM, key.pid);
                event->details.network_connect.destination_port = 0;
                event->details.network_connect.destination_ip[0] = '\0';
                event->details.network_connect.protocol[0] = '\0';
                bpf_ringbuf_submit(event, 0);
            }
            return -EACCES; // Block connection synchronously!
        }
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_NETWORK_CONNECT, SRC_BPF_LSM, key.pid);

        if (family == 2) {
            // IPv4 — struct sockaddr_in: sa_family(2) + sin_port(2) + sin_addr(4)
            uint16_t port_be = 0;
            uint32_t addr_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), (char *)address + 2);
            bpf_probe_read_kernel(&addr_be, sizeof(addr_be), (char *)address + 4);

            // Convert port from big-endian
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);

            // Format IP as dotted-decimal string in the buffer (safe — fixed 4-byte struct)
            unsigned char *b = (unsigned char *)&addr_be;
            uint8_t ip_buf[4];
            bpf_probe_read_kernel(ip_buf, sizeof(ip_buf), b);
            // BPF can't call sprintf; embed octets as individual chars safely
            // Using a fixed-width decimal encoding workaround for BPF verifier
            // The userspace side (C++) will parse the raw bytes if needed.
            // For now, encode as 4 raw bytes + null in the first 5 bytes
            // to distinguish from a human-readable string.
            // Mark as raw-IPv4 with magic prefix byte 0x04:
            event->details.network_connect.destination_ip[0] = 0x04; // raw IPv4 marker
            event->details.network_connect.destination_ip[1] = ip_buf[0];
            event->details.network_connect.destination_ip[2] = ip_buf[1];
            event->details.network_connect.destination_ip[3] = ip_buf[2];
            event->details.network_connect.destination_ip[4] = ip_buf[3];
            event->details.network_connect.destination_ip[5] = 0;
        } else if (family == 10) {
            // IPv6 — struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16)
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), (char *)address + 2);
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            // Mark as raw-IPv6 with magic prefix byte 0x06:
            event->details.network_connect.destination_ip[0] = 0x06; // raw IPv6 marker
            bpf_probe_read_kernel(event->details.network_connect.destination_ip + 1,
                                  16, (char *)address + 8);
            event->details.network_connect.destination_ip[17] = 0;
        } else {
            // Unix Domain Socket (AF_UNIX) - local/IPC
            event->details.network_connect.destination_port = 0;
            event->details.network_connect.destination_ip[0] = 0x01; // Unix socket marker
            bpf_probe_read_kernel_str(event->details.network_connect.destination_ip + 1,
                                      45, (char *)address + 2);
        }

        event->details.network_connect.protocol[0] = 'T';
        event->details.network_connect.protocol[1] = 'C';
        event->details.network_connect.protocol[2] = 'P';
        event->details.network_connect.protocol[3] = 0;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm) {
    if (!bprm)
        return 0;

    struct process_key key = get_current_process_key();

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    // Look up executable file inode to check trust level
    struct file *bprm_file = BPF_CORE_READ(bprm, file);
    if (bprm_file) {
        struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            uint32_t *trust_val = bpf_map_lookup_elem(&trusted_exec_inodes, &ino);
            if (trust_val) {
                uint32_t threshold = *trust_val;
                if (threshold == 0) {
                    return -EACCES;
                }
                bpf_map_update_elem(&process_threshold_map, &key, &threshold, BPF_ANY);
            } else if (blocking_enabled) {
                // If blocking is enabled, untrusted files default to Threshold = 1 (Untrusted)
                uint32_t threshold = 1;
                bpf_map_update_elem(&process_threshold_map, &key, &threshold, BPF_ANY);
            }
        }
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        event->details.process_create.child_pid = key.pid;

        uint32_t ppid = 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct task_struct *real_parent;
            bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
            if (real_parent) {
                bpf_probe_read_kernel(&ppid, sizeof(ppid), &real_parent->tgid);
            }
        }

        fill_header(event, EVT_PROCESS_CREATE, SRC_BPF_LSM, ppid);
        event->details.process_create.real_parent_pid = ppid;

        const char *filename = 0;
        bpf_probe_read_kernel(&filename, sizeof(filename), &bprm->filename);
        if (filename) {
            bpf_probe_read_kernel_str(&event->details.process_create.child_image_path,
                                      sizeof(event->details.process_create.child_image_path), filename);
            bpf_probe_read_kernel_str(&event->details.process_create.child_command_line,
                                      sizeof(event->details.process_create.child_command_line), filename);
        } else {
            event->details.process_create.child_image_path[0] = '\0';
            event->details.process_create.child_command_line[0] = '\0';
        }

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    if (!child) return 0;

    struct process_key key = get_current_process_key();

    // Fix 8/11: Emit EVT_PTRACE_ATTACH telemetry on EVERY ptrace attempt,
    // regardless of trust level. This allows the agent to correlate injection
    // attempts on high-value targets (browser, ssh-agent, gpg-agent) even when
    // both processes appear trusted.
    uint32_t tracee_pid = BPF_CORE_READ(child, tgid);
    struct TelemetryEvent *ptrace_evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (ptrace_evt) {
        fill_header(ptrace_evt, EVT_PTRACE_ATTACH, SRC_BPF_LSM, key.pid);
        ptrace_evt->details.ptrace_attach.tracee_pid = tracee_pid;
        ptrace_evt->details.ptrace_attach.mode       = mode;
        bpf_ringbuf_submit(ptrace_evt, 0);
    }

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    if (mode_val && *mode_val == 1) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold && *threshold == 1) {
            return -EACCES; // Block untrusted process from ptrace attachments!
        }
    }

    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma,
             unsigned long start, unsigned long end, unsigned long newprot) {
    // Only care about PROT_EXEC changes
    if (!(newprot & 0x4)) // PROT_EXEC = 4
        return 0;

    struct process_key key = get_current_process_key();

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    struct file *vm_file = BPF_CORE_READ(vma, vm_file);

    if (mode_val && *mode_val == 1) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold && *threshold == 1) {
            if (!vm_file) { // Anonymous memory region -> Shellcode injection prevention!
                return -EACCES;
            }
        }
    }

    // Emit telemetry for both anonymous and file-backed PROT_EXEC changes.
    // Fix 6: For file-backed VMAs (vm_file != NULL), include the backing file's
    // inode so the agent can detect module stomping (overwriting .text of a
    // loaded .so). Use EVT_MEMORY_PROTECT so the agent can distinguish this
    // from a normal anonymous mmap (EVT_MEMORY_MAP).
    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        uint8_t evt_type = vm_file ? EVT_MEMORY_PROTECT : EVT_MEMORY_MAP;
        fill_header(event, evt_type, SRC_BPF_LSM, key.pid);
        event->details.memory_map.addr       = start;
        event->details.memory_map.length     = end - start;
        event->details.memory_map.prot       = (uint32_t)newprot;
        event->details.memory_map.flags      = 0;
        event->details.memory_map.fd         = -1;
        // Fix 6: populate file_inode for file-backed regions
        if (vm_file) {
            struct inode *inode = BPF_CORE_READ(vm_file, f_inode);
            event->details.memory_map.file_inode = inode ?
                BPF_CORE_READ(inode, i_ino) : 0;
        } else {
            event->details.memory_map.file_inode = 0;
        }
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

// Fix 10: lsm/mmap_file hook — SO/shared-library load telemetry.
// Fires whenever a file-backed executable mapping is created (i.e. when the
// dynamic linker maps a .so into a process). This allows the agent to detect
// unsigned or unexpected module loads into trusted processes, enabling
// detection of DLL/SO side-loading and unexpected LOLBin module loads.
SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
    // Only interested in executable file mappings (shared library loads)
    if (!file) return 0;
    if (!(prot & 0x4)) return 0; // PROT_EXEC = 4

    struct process_key key = get_current_process_key();

    // Skip absolutely-trusted processes (e.g., kinnector itself)
    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (!event) return 0;

    fill_header(event, EVT_IMAGE_LOAD, SRC_BPF_LSM, key.pid);

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    event->details.image_load.file_inode = inode ? BPF_CORE_READ(inode, i_ino) : 0;

    // Extract the dentry (file) name — limited to 256 bytes in the BPF struct
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        bpf_probe_read_kernel_str(
            event->details.image_load.module_path,
            sizeof(event->details.image_load.module_path),
            BPF_CORE_READ(dentry, d_name.name));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog) {
    if (!sock) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;

    uint16_t port = BPF_CORE_READ(sk, __sk_common.skc_num);

    // If port is VNC (5900-5910) or RDP (3389)
    if ((port >= 5900 && port <= 5910) || port == 3389) {
        struct process_key key = get_current_process_key();

        uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
        if (trusted && *trusted == 1)
            return 0;

        uint32_t config_idx = 0;
        uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
        if (mode_val && *mode_val == 1) {
            uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
            if (threshold && *threshold == 1) {
                return -EACCES; // Block listening on VNC/RDP ports!
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// eBPF Tracepoints (Fallback Mode — for kernels without BPF LSM)
// P2-1: sys_enter_execve — emit ProcessCreate events
// ---------------------------------------------------------------------------

struct sys_enter_execve_args {
    unsigned long long pad;
    long syscall_nr;
    char *filename;
    char **argv;
    char **envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct sys_enter_execve_args *ctx) {
    struct process_key key = get_current_process_key();
    uint32_t ppid = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *real_parent;
        bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
        if (real_parent) {
            bpf_probe_read_kernel(&ppid, sizeof(ppid), &real_parent->tgid);
        }
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_PROCESS_CREATE, SRC_BPF_TRACEPOINT, ppid);
        event->details.process_create.child_pid      = key.pid;
        event->details.process_create.real_parent_pid = ppid;
        if (ctx->filename) {
            bpf_probe_read_user_str(&event->details.process_create.child_image_path,
                                    sizeof(event->details.process_create.child_image_path),
                                    ctx->filename);
            bpf_probe_read_user_str(&event->details.process_create.child_command_line,
                                    sizeof(event->details.process_create.child_command_line),
                                    ctx->filename);
        } else {
            event->details.process_create.child_image_path[0] = '\0';
            event->details.process_create.child_command_line[0] = '\0';
        }
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-10: sched/sched_process_exit — emit ProcessStop events
SEC("tracepoint/sched/sched_process_exit")
int tracepoint_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct process_key key = get_current_process_key();

    // Clean up all per-process BPF maps
    bpf_map_delete_elem(&category_flags_map,      &key);
    bpf_map_delete_elem(&pending_network_connect,  &key);
    bpf_map_delete_elem(&trusted_ancestor_roots,   &key);
    bpf_map_delete_elem(&process_threshold_map,    &key);
    bpf_map_delete_elem(&tainted_process_map,      &key);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_PROCESS_STOP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.process_stop.exit_code = 0;
        event->details.process_stop._pad = 0;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-2: sys_enter_connect — emit NetworkConnect with real IP (fallback mode)
struct sys_enter_connect_args {
    unsigned long long pad;
    long syscall_nr;
    int fd;
    struct sockaddr *uservaddr;
    int addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct sys_enter_connect_args *ctx) {
    if (!ctx->uservaddr)
        return 0;

    unsigned short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &ctx->uservaddr->sa_family);
    if (family != 2 && family != 10)
        return 0;

    struct process_key key = get_current_process_key();

    uint32_t conn_active = 1;
    bpf_map_update_elem(&pending_network_connect, &key, &conn_active, BPF_ANY);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_NETWORK_CONNECT, SRC_BPF_TRACEPOINT, key.pid);

        if (family == 2) {
            uint16_t port_be = 0;
            uint32_t addr_be = 0;
            bpf_probe_read_user(&port_be, sizeof(port_be), (char *)ctx->uservaddr + 2);
            bpf_probe_read_user(&addr_be, sizeof(addr_be), (char *)ctx->uservaddr + 4);
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            uint8_t ip_buf[4];
            bpf_probe_read_user(ip_buf, sizeof(ip_buf), &addr_be);
            event->details.network_connect.destination_ip[0] = 0x04;
            event->details.network_connect.destination_ip[1] = ip_buf[0];
            event->details.network_connect.destination_ip[2] = ip_buf[1];
            event->details.network_connect.destination_ip[3] = ip_buf[2];
            event->details.network_connect.destination_ip[4] = ip_buf[3];
            event->details.network_connect.destination_ip[5] = 0;
        } else {
            uint16_t port_be = 0;
            bpf_probe_read_user(&port_be, sizeof(port_be), (char *)ctx->uservaddr + 2);
            event->details.network_connect.destination_port =
                ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            event->details.network_connect.destination_ip[0] = 0x06;
            bpf_probe_read_user(event->details.network_connect.destination_ip + 1,
                                16, (char *)ctx->uservaddr + 8);
            event->details.network_connect.destination_ip[17] = 0;
        }

        event->details.network_connect.protocol[0] = 'T';
        event->details.network_connect.protocol[1] = 'C';
        event->details.network_connect.protocol[2] = 'P';
        event->details.network_connect.protocol[3] = 0;

        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-4: sys_enter_openat — emit FileOpen events in fallback mode
struct sys_enter_openat_args {
    unsigned long long pad;
    long syscall_nr;
    int dfd;
    char *filename;
    int flags;
    int mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct sys_enter_openat_args *ctx) {
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_FILE_READ, SRC_BPF_TRACEPOINT, key.pid);
        event->details.file_read.bytes_requested = 0;
        event->details.file_read.zone_id = 0;
        if (ctx->filename) {
            bpf_probe_read_user_str(&event->details.file_read.file_path,
                                    sizeof(event->details.file_read.file_path),
                                    ctx->filename);
        } else {
            event->details.file_read.file_path[0] = '\0';
        }
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-5/P2-6: sys_enter_mmap + sys_enter_mprotect — MemoryMap events for anonymous exec detection
struct sys_enter_mmap_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint_sys_enter_mmap(struct sys_enter_mmap_args *ctx) {
    // Only interested in anonymous PROT_EXEC mappings (RCE / shellcode indicator)
    if (!(ctx->prot & 0x4)) // PROT_EXEC
        return 0;
    if (!(ctx->flags & 0x20)) // MAP_ANONYMOUS
        return 0;

    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_MEMORY_MAP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.memory_map.addr   = ctx->addr;
        event->details.memory_map.length = ctx->len;
        event->details.memory_map.prot   = (uint32_t)ctx->prot;
        event->details.memory_map.flags  = (uint32_t)ctx->flags;
        event->details.memory_map.fd     = (int32_t)ctx->fd;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

struct sys_enter_mprotect_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned long start;
    size_t len;
    unsigned long prot;
};

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tracepoint_sys_enter_mprotect(struct sys_enter_mprotect_args *ctx) {
    // Only interested in adding PROT_EXEC to an existing mapping
    if (!(ctx->prot & 0x4)) // PROT_EXEC
        return 0;

    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_MEMORY_MAP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.memory_map.addr   = ctx->start;
        event->details.memory_map.length = ctx->len;
        event->details.memory_map.prot   = (uint32_t)ctx->prot;
        event->details.memory_map.flags  = 0;
        event->details.memory_map.fd     = -1;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// P2-7: sys_enter_dup2 + sys_enter_dup3 — emit Dup2 events for reverse shell detection (M-02 fix)
// A process redirecting stdin/stdout/stderr (fd 0/1/2) to a socket is a classic reverse shell indicator.

struct sys_enter_dup2_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned int oldfd;
    unsigned int newfd;
};

SEC("tracepoint/syscalls/sys_enter_dup2")
int tracepoint_sys_enter_dup2(struct sys_enter_dup2_args *ctx) {
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_DUP2, SRC_BPF_TRACEPOINT, key.pid);
        event->details.dup2.oldfd = ctx->oldfd;
        event->details.dup2.newfd = ctx->newfd;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

struct sys_enter_dup3_args {
    unsigned long long pad;
    long syscall_nr;
    unsigned int oldfd;
    unsigned int newfd;
    int flags;
};

SEC("tracepoint/syscalls/sys_enter_dup3")
int tracepoint_sys_enter_dup3(struct sys_enter_dup3_args *ctx) {
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_DUP2, SRC_BPF_TRACEPOINT, key.pid);
        event->details.dup2.oldfd = ctx->oldfd;
        event->details.dup2.newfd = ctx->newfd;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

struct sys_enter_listen_args {
    unsigned long long pad;
    long syscall_nr;
    int fd;
    int backlog;
};

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint_sys_enter_listen(struct sys_enter_listen_args *ctx) {
    struct process_key key = get_current_process_key();

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_LISTEN, SRC_BPF_TRACEPOINT, key.pid);
        event->details.process_create.child_pid = 0;
        event->details.process_create.real_parent_pid = 0;
        event->details.process_create.child_image_path[0] = '\0';
        event->details.process_create.child_command_line[0] = '\0';
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

#define UNIX98_PTY_SLAVE_MAJOR 136

static __always_inline bool is_pty_file(struct file *file) {
    if (!file) return false;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return false;
    unsigned int rdev = BPF_CORE_READ(inode, i_rdev);
    unsigned int major = (rdev >> 8) & 0xfff;
    return major == UNIX98_PTY_SLAVE_MAJOR;
}

SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe_tty_write, struct file *file, const char *buf, size_t count) {
    if (!is_pty_file(file))
        return 0;

    struct tty_event *ev = bpf_ringbuf_reserve(&tty_ringbuf, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->is_write = 1;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    uint32_t to_copy = count > 1023 ? 1023 : count;
    ev->len = to_copy;

    bpf_probe_read_user(&ev->data, to_copy, buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/tty_read")
int BPF_KPROBE(kprobe_tty_read, struct file *file, char *buf, size_t count) {
    if (!is_pty_file(file))
        return 0;

    uint32_t tid = bpf_get_current_pid_tgid();
    struct tty_read_req req = {
        .file = file,
        .buf = buf
    };
    bpf_map_update_elem(&pending_tty_reads, &tid, &req, BPF_ANY);
    return 0;
}

SEC("kretprobe/tty_read")
int BPF_KRETPROBE(kretprobe_tty_read, int ret) {
    uint32_t tid = bpf_get_current_pid_tgid();
    struct tty_read_req *req = bpf_map_lookup_elem(&pending_tty_reads, &tid);
    if (!req)
        return 0;

    struct file *file = req->file;
    char *buf = req->buf;
    bpf_map_delete_elem(&pending_tty_reads, &tid);

    if (ret <= 0)
        return 0;

    struct tty_event *ev = bpf_ringbuf_reserve(&tty_ringbuf, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->is_write = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    uint32_t to_copy = ret > 1023 ? 1023 : ret;
    ev->len = to_copy;

    bpf_probe_read_user(&ev->data, to_copy, buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
