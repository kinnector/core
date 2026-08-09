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
#define EVT_FILE_BATCH      26


// TelemetrySource constants
#define SRC_BPF_LSM         6
#define SRC_BPF_TRACEPOINT  7

#ifndef EACCES
#define EACCES 13
#endif

#ifndef EPERM
#define EPERM 1
#endif

// Role flag: set in process_threshold_map value for known database processes
#define ROLE_DATABASE 0x80000000u

#define PROFILE_ZERO_EXECUTION     0x10000000u
#define PROFILE_RESTRICTED_EXEC    0x20000000u
#define PROFILE_SHELL_ENABLED      0x40000000u
#define PROFILE_ZERO_NETWORK       0x80000000u
#define PROFILE_PATH_CONSTRAINED   0x01000000u

#define ROLE_MAIL_GATEWAY          0x02000000u
#define ROLE_QUEUE_MANAGER         0x04000000u
#define ROLE_NTP_CLIENT            0x08000000u

#define TREE_ADMIN_SESSION         0x00010000u
#define TREE_TRUSTED_ADMIN         0x00020000u
#define TREE_AUTOMATION            0x00040000u
#define TREE_INSTALL_CONTEXT       0x00080000u

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

// Map: (pid, start_time) -> category bitmask (sensitive file categories opened)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct process_key);
    __type(value, uint32_t);
} category_flags_map SEC(".maps");

// Map: (pid, start_time) -> pending network connect flags (non-zero = active outbound)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct process_key);
    __type(value, uint32_t);
} pending_network_connect SEC(".maps");

// Map: (pid, start_time) -> trusted state (1 = absolutely trusted)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct process_key);
    __type(value, uint8_t);
} trusted_ancestor_roots SEC(".maps");

// Map: Inode -> Category ID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, uint64_t);
    __type(value, uint32_t);
} sensitive_inodes_map SEC(".maps");

// Map: Inode -> TrustLevel (2 = Verified, 3 = Naked TTY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, uint64_t);
    __type(value, uint32_t);
} trusted_exec_inodes SEC(".maps");

// Map: (pid, start_time) -> threshold (1 = Untrusted, 2 = Verified, 3 = Naked TTY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct process_key);
    __type(value, uint32_t);
} process_threshold_map SEC(".maps");

// Map: Config Key (0 = blocking_enabled, 1 = sshd_uid) -> Value
#define CONFIG_BLOCKING_ENABLED 0
#define CONFIG_SSHD_UID          1
#define CONFIG_HOST_MNT_NS       2
#define CONFIG_HOST_PID_NS       3
#define CONFIG_HOST_NET_NS       4

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
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

// Map: directory inode -> 1 (bypass telemetry for DB data dirs).
// Only honoured for processes with ROLE_DATABASE set in process_threshold_map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint64_t);   // directory inode number
    __type(value, uint8_t);  // 1 = bypass
} bypassed_directories SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint32_t);
    __type(value, uint32_t);
} pid_tree_type_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint8_t);
} jvm_exception_pids SEC(".maps");

struct db_allowlist_key {
    uint32_t pid;
    uint32_t ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct db_allowlist_key);
    __type(value, uint8_t);
} db_outbound_allowlist SEC(".maps");

struct infra_allowlist_key {
    uint32_t pid;
    uint32_t ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct infra_allowlist_key);
    __type(value, uint8_t);
} infra_outbound_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, uint8_t);
} exec_allowlist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, uint64_t);
    __type(value, uint8_t);
} trusted_admin_binaries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint32_t);
    __type(value, uint8_t);
} admin_session_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, uint64_t);
    __type(value, uint8_t);
} newly_created_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, uint64_t);
    __type(value, uint8_t);
} protected_static_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint32_t);
    __type(value, uint8_t);
} env_read_count_map SEC(".maps");

// P2-9: Per-CPU atomic sequence counter for event ordering
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} seq_counter SEC(".maps");

struct fs_batch_key {
    uint32_t pid;
    uint32_t op_type; // 1 = READ, 2 = WRITE, 3 = DELETE, 4 = MMAP_EXEC, 5 = EXEC, 6 = SYSCALL
    uint64_t inode;
};

struct fs_batch_value {
    uint64_t count;
    uint64_t last_flush;
    char file_path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct fs_batch_key);
    __type(value, struct fs_batch_value);
} fs_batch_map SEC(".maps");

struct scratch_buf {
    char path[256];
    struct fs_batch_value new_val;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct scratch_buf);
} scratch_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, uint64_t);
} dns_cache_map SEC(".maps");


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline bool is_env_file(const char *name) {
    #pragma unroll
    for (int i = 0; i < 28; i++) {
        if (name[i] == '.' && name[i+1] == 'e' && name[i+2] == 'n' && name[i+3] == 'v') {
            return true;
        }
        if (name[i] == '\0') break;
    }
    return false;
}

static __always_inline bool is_git_file(const char *name) {
    #pragma unroll
    for (int i = 0; i < 28; i++) {
        if (name[i] == '.' && name[i+1] == 'g' && name[i+2] == 'i' && name[i+3] == 't') {
            return true;
        }
        if (name[i] == '\0') break;
    }
    return false;
}
static __always_inline bool is_private_ip(uint32_t ip_be) {
    uint32_t ip = __builtin_bswap32(ip_be);
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return true;
    return false;
}

static __always_inline uint32_t get_current_mnt_ns_inum() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns) return 0;
    return BPF_CORE_READ(mnt_ns, ns.inum);
}

static __always_inline uint32_t get_current_pid_ns_inum() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid) return 0;
    unsigned int level = BPF_CORE_READ(pid, level);
    if (level > 4) return 0;
    struct pid_namespace *pid_ns = BPF_CORE_READ(pid, numbers[level].ns);
    if (!pid_ns) return 0;
    return BPF_CORE_READ(pid_ns, ns.inum);
}

static __always_inline uint32_t get_current_net_ns_inum() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;
    struct net *net = BPF_CORE_READ(nsproxy, net_ns);
    if (!net) return 0;
    return BPF_CORE_READ(net, ns.inum);
}

// ---------------------------------------------------------------------------
// Container Identification & Privilege Exemption Helpers
// ---------------------------------------------------------------------------

static __always_inline int is_container_process() {
    uint32_t host_mnt_ns_idx = CONFIG_HOST_MNT_NS;
    uint32_t *host_mnt_ns = bpf_map_lookup_elem(&config_map, &host_mnt_ns_idx);
    if (host_mnt_ns && *host_mnt_ns > 0) {
        uint32_t current_mnt_ns = get_current_mnt_ns_inum();
        if (current_mnt_ns != *host_mnt_ns) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int is_container_restricted() {
    if (!is_container_process()) {
        return 0; // Not inside a container namespace
    }

    uint32_t host_pid_ns_idx = CONFIG_HOST_PID_NS;
    uint32_t *host_pid_ns = bpf_map_lookup_elem(&config_map, &host_pid_ns_idx);
    uint32_t host_net_ns_idx = CONFIG_HOST_NET_NS;
    uint32_t *host_net_ns = bpf_map_lookup_elem(&config_map, &host_net_ns_idx);

    if (host_pid_ns && *host_pid_ns > 0) {
        if (get_current_pid_ns_inum() == *host_pid_ns) {
            return 0; // Exempt host-PID sharing containers (e.g. CSI/CNI drivers)
        }
    }
    if (host_net_ns && *host_net_ns > 0) {
        if (get_current_net_ns_inum() == *host_net_ns) {
            return 0; // Exempt host-NET sharing containers
        }
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    if (current_task) {
        const struct cred *cred = BPF_CORE_READ(current_task, cred);
        if (cred) {
            kernel_cap_t cap_effective = BPF_CORE_READ(cred, cap_effective);
            if (cap_effective.val & (1ULL << 21)) { // CAP_SYS_ADMIN
                return 0; // Exempt privileged admin containers
            }
        }
    }

    return 1; // Restricted container process
}

static __always_inline int is_admin_session() {
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &pid);
    if (tree_type && (*tree_type & TREE_ADMIN_SESSION)) {
        return 1;
    }
    return 0;
}

static __always_inline int is_install_session() {
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &pid);
    if (tree_type && (*tree_type & TREE_INSTALL_CONTEXT)) {
        return 1;
    }
    return 0;
}


static __always_inline bool is_install_binary(const char *name) {
    #pragma unroll
    for (int i = 0; i < 90; i++) {
        if (name[i] == '\0') break;
        if (name[i] == '/' && name[i+1] == 'n' && name[i+2] == 'p' && name[i+3] == 'm') return true;
        if (name[i] == '/' && name[i+1] == 'y' && name[i+2] == 'a' && name[i+3] == 'r' && name[i+4] == 'n') return true;
        if (name[i] == '/' && name[i+1] == 'p' && name[i+2] == 'n' && name[i+3] == 'p' && name[i+4] == 'm') return true;
        if (name[i] == '/' && name[i+1] == 'p' && name[i+2] == 'i' && name[i+3] == 'p') return true;
        if (name[i] == '/' && name[i+1] == 'c' && name[i+2] == 'o' && name[i+3] == 'm' && name[i+4] == 'p' && name[i+5] == 'o' && name[i+6] == 's' && name[i+7] == 'e' && name[i+8] == 'r') return true;
        if (name[i] == '/' && name[i+1] == 'c' && name[i+2] == 'a' && name[i+3] == 'r' && name[i+4] == 'g' && name[i+5] == 'o') return true;
        if (name[i] == '/' && name[i+1] == 'g' && name[i+2] == 'e' && name[i+3] == 'm') return true;
        if (name[i] == '/' && name[i+1] == 'b' && name[i+2] == 'u' && name[i+3] == 'n' && name[i+4] == 'd' && name[i+5] == 'l' && name[i+6] == 'e') return true;
        if (name[i] == '/' && name[i+1] == 'g' && name[i+2] == 'r' && name[i+3] == 'a' && name[i+4] == 'd' && name[i+5] == 'l' && name[i+6] == 'e') return true;
        if (name[i] == '/' && name[i+1] == 'm' && name[i+2] == 'v' && name[i+3] == 'n') return true;
        if (name[i] == '/' && name[i+1] == 'a' && name[i+2] == 'p' && name[i+3] == 't') return true;
        if (name[i] == '/' && name[i+1] == 'd' && name[i+2] == 'p' && name[i+3] == 'k' && name[i+4] == 'g') return true;
    }
    if (name[0] == 'n' && name[1] == 'p' && name[2] == 'm' && name[3] == '\0') return true;
    if (name[0] == 'y' && name[1] == 'a' && name[2] == 'r' && name[3] == 'n' && name[4] == '\0') return true;
    if (name[0] == 'p' && name[1] == 'i' && name[2] == 'p' && name[3] == '\0') return true;
    if (name[0] == 'c' && name[1] == 'a' && name[2] == 'r' && name[3] == 'g' && name[4] == 'o' && name[5] == '\0') return true;
    return false;
}

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

static __always_inline void format_ip_port(char *buf, unsigned char *b, uint16_t port) {
    int offset = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        unsigned char val = b[i];
        if (val >= 100) {
            buf[offset++] = '0' + (val / 100);
            buf[offset++] = '0' + ((val % 100) / 10);
            buf[offset++] = '0' + (val % 10);
        } else if (val >= 10) {
            buf[offset++] = '0' + (val / 10);
            buf[offset++] = '0' + (val % 10);
        } else {
            buf[offset++] = '0' + val;
        }
        if (i < 3) {
            buf[offset++] = '.';
        }
    }
    buf[offset++] = ':';

    uint16_t p = port;
    char port_digits[5];
    port_digits[4] = '0' + (p % 10); p /= 10;
    port_digits[3] = '0' + (p % 10); p /= 10;
    port_digits[2] = '0' + (p % 10); p /= 10;
    port_digits[1] = '0' + (p % 10); p /= 10;
    port_digits[0] = '0' + (p % 10);

    bool leading_zero = true;
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (leading_zero && port_digits[i] == '0' && i < 4) {
            // skip
        } else {
            leading_zero = false;
            buf[offset++] = port_digits[i];
        }
    }
    buf[offset] = '\0';
}

static __always_inline void record_and_batch_event(uint32_t op_type, struct file *file, uint64_t ino, const char *direct_name) {
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct fs_batch_key key = {0};
    key.pid = pid;
    key.op_type = op_type;
    key.inode = ino;

    struct fs_batch_value *val = bpf_map_lookup_elem(&fs_batch_map, &key);
    uint64_t now = bpf_ktime_get_ns();

    if (val) {
        val->count++;
        // If 1 second (1,000,000,000 ns) has passed since last flush, or count > 500
        if (now - val->last_flush > 1000000000ULL || val->count > 500) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, EVT_FILE_BATCH, SRC_BPF_LSM, pid);
                uint32_t *op_ptr = (uint32_t *)&event->details.details_buffer[0];
                uint32_t *cnt_ptr = (uint32_t *)&event->details.details_buffer[4];
                char *path_ptr = (char *)&event->details.details_buffer[8];

                *op_ptr = op_type;
                *cnt_ptr = (uint32_t)val->count;
                bpf_probe_read_kernel(path_ptr, 256, val->file_path);

                bpf_ringbuf_submit(event, 0);
            }
            val->count = 0;
            val->last_flush = now;
        }
    } else {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            __builtin_memset(&buf->new_val, 0, sizeof(buf->new_val));
            buf->new_val.count = 1;
            buf->new_val.last_flush = now;
            if (file) {
                struct qstr d_name;
                bpf_probe_read_kernel(&d_name, sizeof(d_name), &BPF_CORE_READ(file, f_path.dentry)->d_name);
                bpf_probe_read_kernel_str(buf->new_val.file_path, sizeof(buf->new_val.file_path), d_name.name);
            } else if (direct_name) {
                bpf_probe_read_kernel_str(buf->new_val.file_path, sizeof(buf->new_val.file_path), direct_name);
            }
            bpf_map_update_elem(&fs_batch_map, &key, &buf->new_val, BPF_ANY);
        }
    }
}

// -------------------------------------------------------------------------------------------
// BPF LSM Hooks
// ---------------------------------------------------------------------------

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int mask) {
    if (!file)
        return 0;

    struct process_key key = get_current_process_key();

    // Block cross-process /proc/<PID>/fd/ access (pidfd_getfd / LFI attack path)
    {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        if (dentry) {
            struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
            if (parent) {
                struct qstr p_name = BPF_CORE_READ(parent, d_name);
                char p_str[8] = {0};
                bpf_probe_read_kernel_str(p_str, sizeof(p_str), p_name.name);
                if (p_str[0] == 'f' && p_str[1] == 'd' && p_str[2] == '\0') {
                    struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
                    if (grandparent) {
                        struct qstr gp_name = BPF_CORE_READ(grandparent, d_name);
                        char gp_str[16] = {0};
                        bpf_probe_read_kernel_str(gp_str, sizeof(gp_str), gp_name.name);
                        
                        uint32_t gp_pid = 0;
                        bool is_numeric = true;
                        #pragma unroll
                        for (int i = 0; i < 10; i++) {
                            char c = gp_str[i];
                            if (c == '\0') break;
                            if (c >= '0' && c <= '9') {
                                gp_pid = gp_pid * 10 + (c - '0');
                            } else {
                                is_numeric = false;
                                break;
                            }
                        }

                        if (is_numeric && gp_pid > 0 && gp_pid != key.pid) {
                            uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
                            if (active_threshold && *active_threshold > 0) {
                                if (!is_admin_session() || is_install_session()) {
                                    return -EACCES;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // If the process is running under the unprivileged sshd user's UID,
    // deny reading files in sensitive folders (home, root, www, opt, srv, etc.).
    uint32_t current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t sshd_uid_key = CONFIG_SSHD_UID;
    uint32_t *sshd_uid = bpf_map_lookup_elem(&config_map, &sshd_uid_key);
    if (sshd_uid && *sshd_uid > 0 && current_uid == *sshd_uid) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (!dentry) break;
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char name[16] = {0};
            bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);
            if (name[0] == 'h' && name[1] == 'o' && name[2] == 'm' && name[3] == 'e' && name[4] == '\0') {
                return -EACCES;
            }
            if (name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't' && name[4] == '\0') {
                return -EACCES;
            }
            if (name[0] == 'w' && name[1] == 'w' && name[2] == 'w' && name[3] == '\0') {
                return -EACCES;
            }
            if (name[0] == 'o' && name[1] == 'p' && name[2] == 't' && name[3] == '\0') {
                return -EACCES;
            }
            if (name[0] == 's' && name[1] == 'r' && name[2] == 'v' && name[3] == '\0') {
                return -EACCES;
            }
            dentry = BPF_CORE_READ(dentry, d_parent);
        }
    }

    // Admin Session Hook: Allow everything EXCEPT dynamic library injection attempts (.so from writable dirs)
    if (is_admin_session() && !is_install_session()) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char filename[64] = {0};
            bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

            // Check if filename contains ".so"
            bool is_library = false;
            #pragma unroll
            for (int i = 0; i < 58; i++) {
                if (filename[i] == '.' && filename[i+1] == 's' && filename[i+2] == 'o') {
                    is_library = true;
                    break;
                }
                if (filename[i] == '\0') {
                    break;
                }
            }

            if (is_library) {
                // Check if directory path is outside /usr/lib, /lib, /usr/local/lib
                // Walk up parents to see if any parent is user-writable (e.g. "tmp", "home", "var")
                struct dentry *curr = dentry;
                bool is_unauthorized_path = false;
                #pragma unroll
                for (int i = 0; i < 6; i++) {
                    curr = BPF_CORE_READ(curr, d_parent);
                    if (!curr) break;
                    struct qstr p_name = BPF_CORE_READ(curr, d_name);
                    char p_str[16] = {0};
                    bpf_probe_read_kernel_str(p_str, sizeof(p_str), p_name.name);
                    if ((p_str[0] == 't' && p_str[1] == 'm' && p_str[2] == 'p' && p_str[3] == '\0') ||
                        (p_str[0] == 'h' && p_str[1] == 'o' && p_str[2] == 'm' && p_str[3] == 'e' && p_str[4] == '\0') ||
                        (p_str[0] == 'u' && p_str[1] == 's' && p_str[2] == 'e' && p_str[3] == 'r' && p_str[4] == '\0') ||
                        (p_str[0] == 'd' && p_str[1] == 'e' && p_str[2] == 'v' && p_str[3] == '\0') ||
                        (p_str[0] == 'm' && p_str[1] == 'n' && p_str[2] == 't' && p_str[3] == '\0')) {
                        is_unauthorized_path = true;
                        break;
                    }
                }
                if (is_unauthorized_path) {
                    return -EACCES; // Block library injection!
                }
            }
        }
        return 0; // Admin session is completely bypassed for non-injected files!
    }

    // Check if the process is absolutely trusted
    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    if (blocking_enabled) {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char filename[64] = {0};
            bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

            // Rule 2: UNIX Socket Protection
            if ((filename[0] == 'd' && filename[1] == 'o' && filename[2] == 'c' && filename[3] == 'k' && filename[4] == 'e' && filename[5] == 'r' && filename[6] == '.' && filename[7] == 's' && filename[8] == 'o' && filename[9] == 'c' && filename[10] == 'k') ||
                (filename[0] == 'c' && filename[1] == 'o' && filename[2] == 'n' && filename[3] == 't' && filename[4] == 'a' && filename[5] == 'i' && filename[6] == 'n' && filename[7] == 'e' && filename[8] == 'r' && filename[9] == 'd' && filename[10] == '.' && filename[11] == 's' && filename[12] == 'o' && filename[13] == 'c' && filename[14] == 'k')) {
                return -EACCES;
            }

            // Rule 3: Container Escape Block
            uint32_t host_mnt_ns_idx = CONFIG_HOST_MNT_NS;
            uint32_t *host_mnt_ns = bpf_map_lookup_elem(&config_map, &host_mnt_ns_idx);
            if (host_mnt_ns && *host_mnt_ns > 0) {
                uint32_t current_mnt_ns = get_current_mnt_ns_inum();
                if (current_mnt_ns != *host_mnt_ns) {
                    if (mask & 0x0002) { // Opening for write
                        if ((filename[0] == 'r' && filename[1] == 'u' && filename[2] == 'n' && filename[3] == 'c' && filename[4] == '\0') ||
                            (filename[0] == 'c' && filename[1] == 'o' && filename[2] == 'n' && filename[3] == 't' && filename[4] == 'a' && filename[5] == 'i' && filename[6] == 'n' && filename[7] == 'e' && filename[8] == 'r' && filename[9] == 'd' && filename[10] == '-' && filename[11] == 's' && filename[12] == 'h' && filename[13] == 'i' && filename[14] == 'm' && filename[15] == '\0')) {
                            return -EACCES; // Block escape write!
                        }
                    }
                }
            }

            uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
            bool is_install = is_install_session();
            if ((threshold && *threshold > 0) || is_install) {
                // 1. Block .git reads unconditionally for all monitored processes (including daemon and forks)
                if (is_git_file(filename)) {
                    return -EACCES;
                }

                // 2. Block spawned subprocesses (untrusted) or install context from reading .env*
                if ((threshold && *threshold == 1) || is_install) {
                    if (is_env_file(filename)) {
                        return -EACCES;
                    }
                }

                // 2. Persistent Boot-Read Rule: allow reading .env exactly once during bootstrap
                if (is_env_file(filename)) {
                    uint32_t pid = key.pid;
                    uint8_t *count = bpf_map_lookup_elem(&env_read_count_map, &pid);
                    if (count) {
                        if (*count >= 1) {
                            return -EACCES;
                        }
                    } else {
                        uint8_t one = 1;
                        bpf_map_update_elem(&env_read_count_map, &pid, &one, BPF_ANY);
                    }
                }
            }
        }
    }

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
            // Check for /proc/<pid>/mem (writes and reads)
            else if (filename[0] == 'm' && filename[1] == 'e' && filename[2] == 'm' && filename[3] == '\0') {
                if (parent_name[0] >= '0' && parent_name[0] <= '9') {
                    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
                    bool is_install_proc = is_install_session();
                    if ((threshold && *threshold > 0) || is_install_proc) {
                        return -EACCES; // Block monitored processes from accessing procfs memory files!
                    }
                }
            }

            if (is_blocked_dev) {
                uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
                bool is_install_proc = is_install_session();
                if ((threshold && *threshold == 1) || is_install_proc) {
                    return -EACCES; // Block synchronously!
                }
            }
        }
    }

    // 2. Sensitive files protection
    uint32_t *category = bpf_map_lookup_elem(&sensitive_inodes_map, &ino);
    if (!category)
        return 0;

    // Check if the process threshold is 1 (Untrusted) or in install context
    if (blocking_enabled) {
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        bool is_install_proc = is_install_session();
        if ((threshold && *threshold == 1) || is_install_proc) {
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

    if (is_install_session() || is_admin_session()) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            record_and_batch_event(1, file, ino, NULL); // 1 = READ
        }
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

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);

    if (blocking_enabled) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            uint8_t *is_protected = bpf_map_lookup_elem(&protected_static_inodes, &ino);
            if (is_protected && *is_protected == 1) {
                if (threshold && *threshold > 0) {
                    return -EACCES; // Block writing to pre-existing static web-root/config files!
                }
            }
        }
    }

    // DB bypass: suppress write telemetry for DB processes writing to their own
    // data directories. Guard: only skip if this process carries ROLE_DATABASE.
    if (threshold && (*threshold & ROLE_DATABASE)) {
        struct path f_path = BPF_CORE_READ(file, f_path);
        struct dentry *dentry = f_path.dentry;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (!dentry) break;
            struct inode *dir_inode = BPF_CORE_READ(dentry, d_inode);
            if (dir_inode) {
                uint64_t ino = BPF_CORE_READ(dir_inode, i_ino);
                uint8_t *bypass = bpf_map_lookup_elem(&bypassed_directories, &ino);
                if (bypass && *bypass == 1)
                    return 0;
            }
            dentry = BPF_CORE_READ(dentry, d_parent);
        }
    }

    if (threshold && *threshold > 0) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            uint8_t val = 1;
            bpf_map_update_elem(&newly_created_inodes, &ino, &val, BPF_ANY);
        }
    }

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

    if (is_install_session() || is_admin_session()) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            record_and_batch_event(2, file, ino, NULL); // 2 = WRITE
        }
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

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // If the process is running under the unprivileged sshd user's UID,
    // deny outbound network connection immediately.
    uint32_t current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t sshd_uid_key = CONFIG_SSHD_UID;
    uint32_t *sshd_uid = bpf_map_lookup_elem(&config_map, &sshd_uid_key);
    if (sshd_uid && *sshd_uid > 0 && current_uid == *sshd_uid) {
        return -EACCES;
    }

    // Bypass network blocking for admin sessions (unless it is an install context)
    if (is_admin_session() && !is_install_session()) {
        return 0;
    }

    uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
    if (trusted && *trusted == 1)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);

    if (blocking_enabled) {
        uint16_t dest_port = 0;
        uint32_t dest_ip = 0;
        if (family == 2) {
            struct sockaddr_in *sin = (struct sockaddr_in *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin->sin_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &sin->sin_addr.s_addr);
        } else if (family == 10) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin6->sin6_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
        }

        // Rule 1: API Port Protection - Block external/public connections to Docker/Kubelet APIs
        if (dest_port == 2375 || dest_port == 2376 || dest_port == 10250 || dest_port == 10255) {
            if (family == 2 && !is_private_ip(dest_ip)) {
                return -EACCES;
            }
        }
    }

    // Egress Port and Role Sandboxing:
    uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (active_threshold && blocking_enabled) {
        uint32_t thresh_val = *active_threshold;

        // Extract destination port & address for role-based/allowlist checks
        uint16_t dest_port = 0;
        uint32_t dest_ip = 0;
        if (family == 2) {
            struct sockaddr_in *sin = (struct sockaddr_in *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin->sin_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
            bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &sin->sin_addr.s_addr);
        } else if (family == 10) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
            uint16_t port_be = 0;
            bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin6->sin6_port);
            dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
        }

        // 1. PROFILE_ZERO_NETWORK: only allow loopback connect attempts (or DNS/NTP for ROLE_NTP_CLIENT)
        if (thresh_val & PROFILE_ZERO_NETWORK) {
            bool is_ntp_bypass = false;
            if ((thresh_val & ROLE_NTP_CLIENT) && (dest_port == 53 || dest_port == 123)) {
                is_ntp_bypass = true;
            }
            if (!is_ntp_bypass) {
                if (family == 2) { // AF_INET
                    struct sockaddr_in *sin = (struct sockaddr_in *)address;
                    uint32_t daddr = 0;
                    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin->sin_addr.s_addr);
                    if (daddr != 0x0100007f) { // 127.0.0.1 in network byte order
                        return -EACCES;
                    }
                } else if (family == 10) { // AF_INET6
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
                    uint8_t addr6[16];
                    bpf_probe_read_kernel(addr6, sizeof(addr6), &sin6->sin6_addr.in6_u.u6_addr8);
                    bool is_loopback6 = true;
                    #pragma unroll
                    for (int i = 0; i < 15; i++) {
                        if (addr6[i] != 0) is_loopback6 = false;
                    }
                    if (addr6[15] != 1) is_loopback6 = false;
                    if (!is_loopback6) {
                        return -EACCES;
                    }
                }
            }
        }

        // 2. ROLE_MAIL_GATEWAY: Only allow DNS (53) and SMTP/S (25, 465, 587)
        if (thresh_val & ROLE_MAIL_GATEWAY) {
            if (family == 2 || family == 10) {
                if (dest_port != 53 && dest_port != 25 && dest_port != 465 && dest_port != 587) {
                    return -EACCES;
                }
            }
        }

        // 3. ROLE_QUEUE_MANAGER: Only allow cluster, management, and DNS ports
        if (thresh_val & ROLE_QUEUE_MANAGER) {
            if (family == 2 || family == 10) {
                if (dest_port != 53 && dest_port != 5672 && dest_port != 5671 && 
                    dest_port != 15672 && dest_port != 4369 && dest_port != 9092 && 
                    dest_port != 9093 && dest_port != 2181) {
                    return -EACCES;
                }
            }
        }

        // 4. ROLE_DATABASE: Only allow DNS (53) and approved replication/cluster peer IPs
        if (thresh_val & ROLE_DATABASE) {
            if (family == 2 || family == 10) {
                if (dest_port != 53) {
                    // Check db_outbound_allowlist
                    struct db_allowlist_key db_key = { key.pid, dest_ip };
                    uint8_t *allowed = bpf_map_lookup_elem(&db_outbound_allowlist, &db_key);
                    if (!allowed || *allowed != 1) {
                        return -EACCES; // Block replication / DB connection unless allowlisted!
                    }
                }
            }
        }

        // 5. General Infrastructure Egress check against infra_outbound_allowlist
        if (family == 2) {
            struct infra_allowlist_key infra_key = { key.pid, dest_ip };
            uint8_t *allowed_infra = bpf_map_lookup_elem(&infra_outbound_allowlist, &infra_key);
            if (allowed_infra && *allowed_infra != 1) {
                return -EACCES;
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
            if (!is_install_session()) {
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

    if (is_install_session() || is_admin_session()) {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            uint16_t dest_port = 0;
            uint32_t dest_ip = 0;
            if (family == 2) {
                struct sockaddr_in *sin = (struct sockaddr_in *)address;
                uint16_t port_be = 0;
                bpf_probe_read_kernel(&port_be, sizeof(port_be), &sin->sin_port);
                dest_port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
                bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &sin->sin_addr.s_addr);

                unsigned char *b = (unsigned char *)&dest_ip;
                format_ip_port(buf->path, b, dest_port);
                record_and_batch_event(7, NULL, dest_port, buf->path); // 7 = NETWORK_CONNECT
            } else if (family == 10) {
                record_and_batch_event(7, NULL, 0, "[IPv6 connection]");
            } else {
                record_and_batch_event(7, NULL, 0, "[Unix socket connection]");
            }
        }
    }

    return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm) {
    if (!bprm)
        return 0;

    struct process_key key = get_current_process_key();
    
    // Check if executing a package manager/install binary to mark the process tree as TREE_INSTALL_CONTEXT
    const char *filename_ptr = 0;
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &bprm->filename);
    if (filename_ptr) {
        char filename[128] = {0};
        bpf_probe_read_kernel_str(filename, sizeof(filename), filename_ptr);
        if (is_install_binary(filename)) {
            uint32_t pid = key.pid;
            uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &pid);
            if (tree_type) {
                *tree_type &= ~TREE_ADMIN_SESSION;
                *tree_type |= TREE_INSTALL_CONTEXT;
            } else {
                uint32_t val = TREE_INSTALL_CONTEXT;
                bpf_map_update_elem(&pid_tree_type_map, &pid, &val, BPF_ANY);
            }
        }
    }

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // If the process is running under the unprivileged sshd user's UID,
    // deny execution of any binary (e.g. shells, tools) immediately.
    uint32_t current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uint32_t sshd_uid_key = CONFIG_SSHD_UID;
    uint32_t *sshd_uid = bpf_map_lookup_elem(&config_map, &sshd_uid_key);
    if (sshd_uid && *sshd_uid > 0 && current_uid == *sshd_uid) {
        return -EACCES;
    }
    // 1. If executing a trusted admin binary (like logrotate), mark the process tree as TRUSTED_ADMIN
    struct inode *bin_inode = BPF_CORE_READ(bprm, file, f_inode);
    if (bin_inode) {
        uint64_t ino = BPF_CORE_READ(bin_inode, i_ino);
        uint8_t *is_admin_bin = bpf_map_lookup_elem(&trusted_admin_binaries, &ino);
        if (is_admin_bin && *is_admin_bin == 1) {
            uint32_t pid = key.pid;
            uint32_t val = TREE_TRUSTED_ADMIN;
            bpf_map_update_elem(&pid_tree_type_map, &pid, &val, BPF_ANY);
        }
    }

    // 2. Enforce execution restrictions on TREE_TRUSTED_ADMIN processes
    uint32_t current_pid = key.pid;
    uint32_t *tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &current_pid);
    if (tree_type && (*tree_type & TREE_TRUSTED_ADMIN)) {
        struct dentry *dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
        if (dentry) {
            char exe_name[32] = {0};
            bpf_probe_read_kernel_str(exe_name, sizeof(exe_name), BPF_CORE_READ(dentry, d_name.name));
            
            bool is_allowed_admin_cmd = false;
            if ((exe_name[0] == 's' && exe_name[1] == 'h' && exe_name[2] == '\0') ||
                (exe_name[0] == 'b' && exe_name[1] == 'a' && exe_name[2] == 's' && exe_name[3] == 'h' && exe_name[4] == '\0') ||
                (exe_name[0] == 'g' && exe_name[1] == 'z' && exe_name[2] == 'i' && exe_name[3] == 'p' && exe_name[4] == '\0') ||
                (exe_name[0] == 'n' && exe_name[1] == 'g' && exe_name[2] == 'i' && exe_name[3] == 'n' && exe_name[4] == 'x' && exe_name[5] == '\0') ||
                (exe_name[0] == 'k' && exe_name[1] == 'i' && exe_name[2] == 'l' && exe_name[3] == 'l' && exe_name[4] == '\0') ||
                (exe_name[0] == 'p' && exe_name[1] == 'o' && exe_name[2] == 's' && exe_name[3] == 't' && exe_name[4] == 'f' && exe_name[5] == 'i' && exe_name[6] == 'x' && exe_name[7] == '\0') ||
                (exe_name[0] == 'm' && exe_name[1] == 'y' && exe_name[2] == 's' && exe_name[3] == 'q' && exe_name[4] == 'l' && exe_name[5] == 'a' && exe_name[6] == 'd' && exe_name[7] == 'm' && exe_name[8] == 'i' && exe_name[9] == 'n' && exe_name[10] == '\0') ||
                (exe_name[0] == 'r' && exe_name[1] == 'e' && exe_name[2] == 'd' && exe_name[3] == 'i' && exe_name[4] == 's' && exe_name[5] == '-' && exe_name[6] == 'c' && exe_name[7] == 'l' && exe_name[8] == 'i' && exe_name[9] == '\0') ||
                (exe_name[0] == 'p' && exe_name[1] == 'g' && exe_name[2] == '_' && exe_name[3] == 'c' && exe_name[4] == 't' && exe_name[5] == 'l' && exe_name[6] == '\0') ||
                (exe_name[0] == 'p' && exe_name[1] == 'g' && exe_name[2] == '_' && exe_name[3] == 'c' && exe_name[4] == 't' && exe_name[5] == 'l' && exe_name[6] == 'c' && exe_name[7] == 'l' && exe_name[8] == 'u' && exe_name[9] == 's' && exe_name[10] == 't' && exe_name[11] == 'e' && exe_name[12] == 'r' && exe_name[13] == '\0') ||
                (exe_name[0] == 'a' && exe_name[1] == 'p' && exe_name[2] == 'a' && exe_name[3] == 'c' && exe_name[4] == 'h' && exe_name[5] == 'e' && exe_name[6] == '2' && exe_name[7] == 'c' && exe_name[8] == 't' && exe_name[9] == 'l' && exe_name[10] == '\0') ||
                (exe_name[0] == 'a' && exe_name[1] == 'p' && exe_name[2] == 'a' && exe_name[3] == 'c' && exe_name[4] == 'h' && exe_name[5] == 'e' && exe_name[6] == '2' && exe_name[7] == '\0') ||
                (exe_name[0] == 'l' && exe_name[1] == 'o' && exe_name[2] == 'g' && exe_name[3] == 'r' && exe_name[4] == 'o' && exe_name[5] == 't' && exe_name[6] == 'a' && exe_name[7] == 't' && exe_name[8] == 'e' && exe_name[9] == '\0')) {
                is_allowed_admin_cmd = true;
            }
            if (!is_allowed_admin_cmd) {
                return -EACCES; // Block non-safe commands from logrotate tree!
            }
        }
    }
    // Rule 4: Privileged Container Detection
    uint32_t host_mnt_ns_idx = CONFIG_HOST_MNT_NS;
    uint32_t *host_mnt_ns = bpf_map_lookup_elem(&config_map, &host_mnt_ns_idx);
    if (host_mnt_ns && *host_mnt_ns > 0) {
        uint32_t current_mnt_ns = get_current_mnt_ns_inum();
        if (current_mnt_ns != *host_mnt_ns) {
            uint32_t host_pid_ns_idx = CONFIG_HOST_PID_NS;
            uint32_t *host_pid_ns = bpf_map_lookup_elem(&config_map, &host_pid_ns_idx);
            uint32_t host_net_ns_idx = CONFIG_HOST_NET_NS;
            uint32_t *host_net_ns = bpf_map_lookup_elem(&config_map, &host_net_ns_idx);

            bool is_privileged = false;
            if (host_pid_ns && *host_pid_ns > 0) {
                if (get_current_pid_ns_inum() == *host_pid_ns) {
                    is_privileged = true;
                }
            }
            if (host_net_ns && *host_net_ns > 0) {
                if (get_current_net_ns_inum() == *host_net_ns) {
                    is_privileged = true;
                }
            }
            
            struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
            if (current_task) {
                const struct cred *cred = BPF_CORE_READ(current_task, cred);
                if (cred) {
                    kernel_cap_t cap_effective = BPF_CORE_READ(cred, cap_effective);
                    if (cap_effective.val & (1ULL << 21)) { // CAP_SYS_ADMIN is bit 21
                        is_privileged = true;
                    }
                }
            }

            if (is_privileged) {
                uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
                if (!trusted || *trusted != 1) {
                    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
                    if (event) {
                        fill_header(event, EVT_IMAGE_LOAD, SRC_BPF_LSM, key.pid);
                        struct dentry *dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
                        if (dentry) {
                            bpf_probe_read_kernel_str(event->details.image_load.module_path,
                                                      sizeof(event->details.image_load.module_path),
                                                      BPF_CORE_READ(dentry, d_name.name));
                        }
                        bpf_ringbuf_submit(event, 0);
                    }
                    return -EACCES; // Block execution of untrusted privileged containers!
                }
            }
        }
    }

    // Detect new login session
    char parent_comm[16] = {0};
    int is_login_parent = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *real_parent;
        bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
        if (real_parent) {
            struct mm_struct *mm = NULL;
            bpf_probe_read_kernel(&mm, sizeof(mm), &real_parent->mm);
            if (mm) {
                struct file *exe_file = NULL;
                bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file);
                if (exe_file) {
                    struct dentry *dentry = NULL;
                    bpf_probe_read_kernel(&dentry, sizeof(dentry), &exe_file->f_path.dentry);
                    if (dentry) {
                        char name[16] = {0};
                        bpf_probe_read_kernel_str(name, sizeof(name), &dentry->d_name.name);
                        if ((name[0] == 's' && name[1] == 's' && name[2] == 'h' && name[3] == 'd' && name[4] == '\0') ||
                            (name[0] == 'l' && name[1] == 'o' && name[2] == 'g' && name[3] == 'i' && name[4] == 'n' && name[5] == '\0')) {
                            
                            struct dentry *parent_dentry = NULL;
                            bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent);
                            if (parent_dentry) {
                                char p_name[16] = {0};
                                bpf_probe_read_kernel_str(p_name, sizeof(p_name), &parent_dentry->d_name.name);
                                if ((p_name[0] == 's' && p_name[1] == 'b' && p_name[2] == 'i' && p_name[3] == 'n' && p_name[4] == '\0') ||
                                    (p_name[0] == 'b' && p_name[1] == 'i' && p_name[2] == 'n' && p_name[3] == '\0')) {
                                    is_login_parent = 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (is_login_parent) {
        struct signal_struct *signal = NULL;
        bpf_probe_read_kernel(&signal, sizeof(signal), &task->signal);
        if (signal) {
            struct tty_struct *tty = NULL;
            bpf_probe_read_kernel(&tty, sizeof(tty), &signal->tty);
            if (tty) {
                // Yes! This is a login session with a TTY/PTY. Stamp it as TREE_ADMIN_SESSION!
                uint32_t pid = key.pid;
                uint32_t flag = TREE_ADMIN_SESSION;
                bpf_map_update_elem(&pid_tree_type_map, &pid, &flag, BPF_ANY);
                uint8_t allowed = 1;
                bpf_map_update_elem(&admin_session_pids, &pid, &allowed, BPF_ANY);
            }
        }
    }

    // Bypass execution blocking for admin sessions (unless it is an install context)
    if (is_admin_session() && !is_install_session()) {
        return 0;
    }

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

    uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (active_threshold && blocking_enabled) {
        // Block execution of any newly created/written files
        if (bprm_file) {
            struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
            if (inode) {
                uint64_t ino = BPF_CORE_READ(inode, i_ino);
                uint8_t *is_newly_created = bpf_map_lookup_elem(&newly_created_inodes, &ino);
                if (is_newly_created && *is_newly_created == 1) {
                    if (active_threshold && *active_threshold > 0) {
                        if (!is_install_session()) {
                            return -EACCES;
                        }
                    }
                }
            }
        }

        uint32_t thresh_val = *active_threshold;

        // PROFILE_ZERO_EXECUTION: unconditionally deny execution
        if (thresh_val & PROFILE_ZERO_EXECUTION) {
            return -EACCES;
        }

        // PROFILE_RESTRICTED_EXEC: check exec_allowlist_map
        if (thresh_val & PROFILE_RESTRICTED_EXEC) {
            if (bprm_file) {
                struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
                if (inode) {
                    uint64_t ino = BPF_CORE_READ(inode, i_ino);
                    uint8_t *allowed = bpf_map_lookup_elem(&exec_allowlist_map, &ino);
                    if (!allowed || *allowed != 1) {
                        return -EACCES; // Deny execution of unapproved binary
                    }
                }
            }
        }
    }

    // Universal Dangerous-Exec Filter: L1 / L2 blocks for known dangerous tools in monitored contexts
    if (bprm_file) {
        struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
        if (inode) {
            char exe_name[32] = {0};
            struct dentry *dentry = BPF_CORE_READ(bprm_file, f_path.dentry);
            if (dentry) {
                bpf_probe_read_kernel_str(exe_name, sizeof(exe_name), BPF_CORE_READ(dentry, d_name.name));
            }

            // Check for dangerous binaries: nc, ncat, netcat, socat, tftp
            bool is_dangerous_tool = false;
            // "nc\0"
            if (exe_name[0] == 'n' && exe_name[1] == 'c' && exe_name[2] == '\0') {
                is_dangerous_tool = true;
            }
            // "ncat"
            else if (exe_name[0] == 'n' && exe_name[1] == 'c' && exe_name[2] == 'a' && exe_name[3] == 't' && exe_name[4] == '\0') {
                is_dangerous_tool = true;
            }
            // "netcat"
            else if (exe_name[0] == 'n' && exe_name[1] == 'e' && exe_name[2] == 't' && exe_name[3] == 'c' && exe_name[4] == 'a' && exe_name[5] == 't' && exe_name[6] == '\0') {
                is_dangerous_tool = true;
            }
            // "socat"
            else if (exe_name[0] == 's' && exe_name[1] == 'o' && exe_name[2] == 'c' && exe_name[3] == 'a' && exe_name[4] == 't' && exe_name[5] == '\0') {
                is_dangerous_tool = true;
            }
            // "tftp"
            else if (exe_name[0] == 't' && exe_name[1] == 'f' && exe_name[2] == 't' && exe_name[3] == 'p' && exe_name[4] == '\0') {
                is_dangerous_tool = true;
            }

            // Check for privilege escalation tools: sudo, su, pkexec, newuidmap, newgidmap
            bool is_priv_esc = false;
            // "sudo"
            if (exe_name[0] == 's' && exe_name[1] == 'u' && exe_name[2] == 'd' && exe_name[3] == 'o' && exe_name[4] == '\0') {
                is_priv_esc = true;
            }
            // "su"
            else if (exe_name[0] == 's' && exe_name[1] == 'u' && exe_name[2] == '\0') {
                is_priv_esc = true;
            }
            // "pkexec"
            else if (exe_name[0] == 'p' && exe_name[1] == 'k' && exe_name[2] == 'e' && exe_name[3] == 'x' && exe_name[4] == 'e' && exe_name[5] == 'c' && exe_name[6] == '\0') {
                is_priv_esc = true;
            }
            // "newuidmap"
            else if (exe_name[0] == 'n' && exe_name[1] == 'e' && exe_name[2] == 'w' && exe_name[3] == 'u' && exe_name[4] == 'i' && exe_name[5] == 'd' && exe_name[6] == 'm' && exe_name[7] == 'a' && exe_name[8] == 'p' && exe_name[9] == '\0') {
                is_priv_esc = true;
            }
            // "newgidmap"
            else if (exe_name[0] == 'n' && exe_name[1] == 'e' && exe_name[2] == 'w' && exe_name[3] == 'g' && exe_name[4] == 'i' && exe_name[5] == 'd' && exe_name[6] == 'm' && exe_name[7] == 'a' && exe_name[8] == 'p' && exe_name[9] == '\0') {
                is_priv_esc = true;
            }

            if ((is_dangerous_tool || is_priv_esc) && blocking_enabled) {
                // If it is in a monitored context (threshold exists and is > 0), block!
                if (active_threshold && *active_threshold > 0) {
                    return -EACCES; // Block dangerous/priv-esc execution in monitored contexts!
                }
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

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm) {
    if (!bprm)
        return 0;

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode && *mode == 1);
    if (!blocking_enabled)
        return 0;

    // Bypass for admin sessions (unless it is install context)
    if (is_admin_session() && !is_install_session()) {
        return 0;
    }

    struct process_key key = get_current_process_key();
    uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!active_threshold) {
        return 0;
    }

    uint32_t thresh_val = *active_threshold;

    struct file *bprm_file = BPF_CORE_READ(bprm, file);
    if (bprm_file) {
        // Block memfd execution for monitored processes / install contexts
        struct dentry *dentry = BPF_CORE_READ(bprm_file, f_path.dentry);
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            char name[16] = {0};
            bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);
            if (name[0] == 'm' && name[1] == 'e' && name[2] == 'm' && name[3] == 'f' && name[4] == 'd' && name[5] == ':') {
                if (thresh_val > 0 || is_install_session()) {
                    return -EACCES;
                }
            }
        }

        struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
        if (inode) {
            uint64_t ino = BPF_CORE_READ(inode, i_ino);
            
            // Re-validate against newly_created_inodes (untrusted/tampered)
            uint8_t *is_newly_created = bpf_map_lookup_elem(&newly_created_inodes, &ino);
            if (is_newly_created && *is_newly_created == 1) {
                if (thresh_val > 0) {
                    if (!is_install_session()) {
                        return -EACCES;
                    }
                }
            }

            // PROFILE_ZERO_EXECUTION: unconditionally deny execution
            if (thresh_val & PROFILE_ZERO_EXECUTION) {
                return -EACCES;
            }

            // PROFILE_RESTRICTED_EXEC: check exec_allowlist_map
            if (thresh_val & PROFILE_RESTRICTED_EXEC) {
                uint8_t *allowed = bpf_map_lookup_elem(&exec_allowlist_map, &ino);
                if (!allowed || *allowed != 1) {
                    return -EACCES; // Deny execution of unapproved binary
                }
            }
        }
    }

    if (is_install_session() || is_admin_session()) {
        struct file *bprm_file = BPF_CORE_READ(bprm, file);
        if (bprm_file) {
            struct inode *inode = BPF_CORE_READ(bprm_file, f_inode);
            uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
            record_and_batch_event(5, bprm_file, ino, NULL); // 5 = EXEC
        }
    }

    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    if (!child) return 0;

    struct process_key key = get_current_process_key();
    uint32_t tracee_pid = BPF_CORE_READ(child, tgid);
    uint32_t tracer_pid = key.pid;

    // Protect admin session from ptrace attempts by non-admin processes
    uint32_t *tracee_tree = bpf_map_lookup_elem(&pid_tree_type_map, &tracee_pid);
    if (tracee_tree && (*tracee_tree & TREE_ADMIN_SESSION)) {
        uint32_t *tracer_tree = bpf_map_lookup_elem(&pid_tree_type_map, &tracer_pid);
        if (!tracer_tree || !(*tracer_tree & TREE_ADMIN_SESSION)) {
            return -EACCES; // Block non-admin tracing admin process!
        }
    }

    // Fix 8/11: Emit EVT_PTRACE_ATTACH telemetry on EVERY ptrace attempt,
    // regardless of trust level. This allows the agent to correlate injection
    // attempts on high-value targets (browser, ssh-agent, gpg-agent) even when
    // both processes appear trusted.
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
        if (threshold && *threshold > 0) {
            if (tracee_pid != tracer_pid) {
                return -EACCES; // Block monitored processes from tracing/reading other processes' memory!
            }
        }
        if (threshold && *threshold == 1) {
            return -EACCES; // Block untrusted process from ptrace attachments!
        }
    }

    return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    if (!p) return 0;

    uint32_t target_pid = BPF_CORE_READ(p, tgid);
    uint32_t current_pid = bpf_get_current_pid_tgid() >> 32;

    // Ignore self-signals
    if (target_pid == current_pid) return 0;

    // Check if target is Warden
    char target_comm[16] = {0};
    bpf_probe_read_kernel_str(target_comm, sizeof(target_comm), &p->comm);
    int is_target_warden = (target_comm[0] == 'w' && target_comm[1] == 'a' && target_comm[2] == 'r' && target_comm[3] == 'd' && target_comm[4] == 'e' && target_comm[5] == 'n');

    // Check if target is admin session
    uint32_t *target_tree = bpf_map_lookup_elem(&pid_tree_type_map, &target_pid);
    int is_target_admin = (target_tree && (*target_tree & TREE_ADMIN_SESSION));

    if (is_target_warden || is_target_admin) {
        // Allow if sender is Warden
        char current_comm[16] = {0};
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            bpf_probe_read_kernel_str(current_comm, sizeof(current_comm), &task->comm);
        }
        int is_sender_warden = (current_comm[0] == 'w' && current_comm[1] == 'a' && current_comm[2] == 'r' && current_comm[3] == 'd' && current_comm[4] == 'e' && current_comm[5] == 'n');
        
        // Allow if sender is admin session
        uint32_t *sender_tree = bpf_map_lookup_elem(&pid_tree_type_map, &current_pid);
        int is_sender_admin = (sender_tree && (*sender_tree & TREE_ADMIN_SESSION));

        if (!is_sender_warden && !is_sender_admin) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, 23, SRC_BPF_LSM, current_pid); // EVT_SIGNAL_DELIVERY = 23
                bpf_probe_read_kernel(event->details.details_buffer, 4, &target_pid);
                bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &sig);
                bpf_ringbuf_submit(event, 0);
            }
            return -EPERM; // Deny signal delivery!
        }
    }

    if (sig == 9 || sig == 19) {
        struct process_key key = get_current_process_key();
        uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (threshold) {
            struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
            if (event) {
                fill_header(event, 23, SRC_BPF_LSM, current_pid); // EVT_SIGNAL_DELIVERY = 23
                bpf_probe_read_kernel(event->details.details_buffer, 4, &target_pid);
                bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &sig);
                bpf_ringbuf_submit(event, 0);
            }
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
    uint32_t blocking_enabled = (mode_val && *mode_val == 1);

    // Block RWX mappings (W^X violation) unless in jvm_exception_pids
    if ((newprot & 0x2) && (newprot & 0x4)) { // PROT_WRITE=2, PROT_EXEC=4
        uint32_t pid = key.pid;
        uint8_t *exc = bpf_map_lookup_elem(&jvm_exception_pids, &pid);
        if (!exc && blocking_enabled) {
            return -EACCES;
        }
    }
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

    if (is_install_session() || is_admin_session()) {
        struct file *vm_file = BPF_CORE_READ(vma, vm_file);
        if (vm_file) {
            struct inode *inode = BPF_CORE_READ(vm_file, f_inode);
            uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
            record_and_batch_event(4, vm_file, ino, NULL); // 4 = MMAP_EXEC (file-backed)
        } else {
            record_and_batch_event(4, NULL, 0, "[anonymous]"); // 4 = MMAP_EXEC (anonymous)
        }
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

    // Check config/blocking mode
    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode_val && *mode_val == 1);

    // Block RWX mappings (W^X violation) unless in jvm_exception_pids
    if (prot & 0x2) { // PROT_WRITE=2 (PROT_EXEC=4 already checked)
        uint32_t pid = key.pid;
        uint8_t *exc = bpf_map_lookup_elem(&jvm_exception_pids, &pid);
        if (!exc && blocking_enabled) {
            return -EACCES;
        }
    }

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

    if (is_install_session() || is_admin_session()) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
        record_and_batch_event(4, file, ino, NULL); // 4 = MMAP_EXEC
    }

    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog) {
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
    if (!path) return 0;

    uint32_t config_idx = 0;
    uint32_t *mode_val = bpf_map_lookup_elem(&config_map, &config_idx);
    uint32_t blocking_enabled = (mode_val && *mode_val == 1);
    if (!blocking_enabled) return 0;

    // If setting any executable permission bits (S_IXUSR, S_IXGRP, S_IXOTH)
    if (mode & (0100 | 0010 | 0001)) {
        struct process_key key = get_current_process_key();
        uint32_t *active_threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
        if (!active_threshold || *active_threshold == 0) {
            return 0; // Not a monitored process, allow chmod
        }

        if (is_admin_session() && !is_install_session()) {
            return 0; // Allow active admin operators (SSH shell, PTY)
        }
        if (is_install_session()) {
            return 0; // Allow package managers to set executable bits during install
        }

        uint8_t *trusted = bpf_map_lookup_elem(&trusted_ancestor_roots, &key);
        if (trusted && *trusted == 1) {
            return 0; // Allow system installers, updates, and trusted tools
        }

        return -EACCES; // Strictly block any other process from making files executable!
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
    uint32_t pid = key.pid;
    bpf_map_delete_elem(&pid_tree_type_map,        &pid);
    bpf_map_delete_elem(&jvm_exception_pids,       &pid);
    bpf_map_delete_elem(&admin_session_pids,       &pid);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, EVT_PROCESS_STOP, SRC_BPF_TRACEPOINT, key.pid);
        event->details.process_stop.exit_code = 0;
        event->details.process_stop._pad = 0;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

// DB-1: sched/sched_process_fork — propagate parent's threshold & trust to forked child.
// Critical for database worker processes (PostgreSQL bgworkers, Redis BGSAVE) that
// are created via fork() without execve, so exec-time hooks never fire for them.
struct sched_process_fork_args {
    unsigned long long pad;
    char parent_comm[16];
    uint32_t parent_pid;
    char child_comm[16];
    uint32_t child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int tracepoint_sched_process_fork(struct sched_process_fork_args *ctx) {
    // Build parent key from parent_pid + start_time via task_struct walk
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct process_key parent_key = {0};
    parent_key.pid = ctx->parent_pid;
    bpf_probe_read_kernel(&parent_key.start_time, sizeof(parent_key.start_time),
                          &task->start_time);

    // Propagate pid_tree_type_map
    uint32_t parent_pid = ctx->parent_pid;
    uint32_t child_pid = ctx->child_pid;
    uint32_t *parent_tree_type = bpf_map_lookup_elem(&pid_tree_type_map, &parent_pid);
    if (parent_tree_type) {
        uint32_t val = *parent_tree_type;
        bpf_map_update_elem(&pid_tree_type_map, &child_pid, &val, BPF_ANY);
    }

    // Propagate jvm_exception_pids
    uint8_t *parent_jvm_exc = bpf_map_lookup_elem(&jvm_exception_pids, &parent_pid);
    if (parent_jvm_exc) {
        uint8_t val = *parent_jvm_exc;
        bpf_map_update_elem(&jvm_exception_pids, &child_pid, &val, BPF_ANY);
    }

    // Propagate admin_session_pids
    uint8_t *parent_admin_pid = bpf_map_lookup_elem(&admin_session_pids, &parent_pid);
    if (parent_admin_pid) {
        uint8_t val = *parent_admin_pid;
        bpf_map_update_elem(&admin_session_pids, &child_pid, &val, BPF_ANY);
    }

    // Look up parent's threshold (contains ROLE_DATABASE flag)
    uint32_t *parent_threshold = bpf_map_lookup_elem(&process_threshold_map, &parent_key);
    uint8_t  *parent_trusted   = bpf_map_lookup_elem(&trusted_ancestor_roots, &parent_key);

    // Only propagate if parent has a meaningful entry
    if (!parent_threshold) {
        asm volatile("" : "+r"(parent_trusted));
        if (!parent_trusted) {
            return 0;
        }
    }

    // Child key: pid from fork args; start_time filled from child task
    // The child's start_time is not yet stable at fork, so we use parent's start_time
    // as a temporary seed — user-space will correct it on next ProcessCreate event.
    struct process_key child_key = {0};
    child_key.pid = ctx->child_pid;
    child_key.start_time = parent_key.start_time; // best-effort at fork time

    if (parent_threshold) {
        uint32_t val = *parent_threshold;
        bpf_map_update_elem(&process_threshold_map, &child_key, &val, BPF_ANY);
    }
    if (parent_trusted) {
        uint8_t val = *parent_trusted;
        bpf_map_update_elem(&trusted_ancestor_roots, &child_key, &val, BPF_ANY);
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

    if (is_install_session() || is_admin_session()) {
        record_and_batch_event(6, NULL, 0, "[dup2]"); // 6 = SYSCALL
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

    if (is_install_session() || is_admin_session()) {
        record_and_batch_event(6, NULL, 0, "[dup3]"); // 6 = SYSCALL
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

    unsigned int uret = (unsigned int)ret;
    uint32_t to_copy = uret > 1023 ? 1023 : uret;
    ev->len = to_copy;

    bpf_probe_read_user(&ev->data, to_copy & 1023, buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Container Sandboxing & Escape Prevention LSM Hooks
// ---------------------------------------------------------------------------

SEC("lsm/sb_mount")
int BPF_PROG(warden_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data) {
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked mount attempt from restricted container namespace\n");
        return -EPERM;
    }
    return 0;
}

SEC("lsm/path_chroot")
int BPF_PROG(warden_path_chroot, const struct path *path) {
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked chroot attempt from restricted container namespace\n");
        return -EPERM;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int tracepoint_sys_enter_setns(void *ctx) {
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked setns attempt: killing container process\n");
        bpf_send_signal(9); // SIGKILL immediately to terminate breakout
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int tracepoint_sys_enter_unshare(void *ctx) {
    if (is_container_restricted()) {
        bpf_printk("[Warden LSM] Blocked unshare attempt: killing container process\n");
        bpf_send_signal(9); // SIGKILL immediately
    }
    return 0;
}

#ifndef bpf_ntohs
#define bpf_ntohs(x) (uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8))
#endif
#ifndef bpf_htons
#define bpf_htons(x) (uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8))
#endif

SEC("lsm/socket_post_accept")
int BPF_PROG(socket_post_accept, struct socket *sock, struct socket *newsock, int flags) {
    if (!newsock || !newsock->sk) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct process_key key = get_current_process_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 20, SRC_BPF_LSM, pid); // EVT_NETWORK_ACCEPT = 20
        struct sock *sk = newsock->sk;
        uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
        event->details.details_buffer[0] = 0;

        uint16_t dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        uint16_t sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        bpf_probe_read_kernel(event->details.details_buffer + 46, 2, &dport);
        bpf_probe_read_kernel(event->details.details_buffer + 48, 2, &sport);

        if (family == 2) {
            uint32_t src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            unsigned char *b = (unsigned char *)&src_ip;
            event->details.details_buffer[0] = 0x04;
            event->details.details_buffer[1] = b[0];
            event->details.details_buffer[2] = b[1];
            event->details.details_buffer[3] = b[2];
            event->details.details_buffer[4] = b[3];
            event->details.details_buffer[5] = 0;
        } else if (family == 10) {
            event->details.details_buffer[0] = 0x06;
            bpf_probe_read_kernel(event->details.details_buffer + 1, 16, &sk->__sk_common.skc_v6_daddr);
            event->details.details_buffer[17] = 0;
        }
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    if (!sock || !sock->sk || !msg) return 0;
    struct sock *sk = sock->sk;
    uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
    uint16_t type = BPF_CORE_READ(sock, type);
    if (type != 2) return 0; // SOCK_DGRAM = 2

    struct sockaddr *address = BPF_CORE_READ(msg, msg_name);
    if (!address) return 0;

    uint16_t dest_port = 0;
    if (family == 2) {
        struct sockaddr_in sin;
        bpf_probe_read_kernel(&sin, sizeof(sin), address);
        dest_port = bpf_ntohs(sin.sin_port);
    } else if (family == 10) {
        struct sockaddr_in6 sin6;
        bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
        dest_port = bpf_ntohs(sin6.sin6_port);
    }

    if (dest_port != 53) return 0;

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    struct process_key key = get_current_process_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    void *user_buf = 0;
    uint8_t iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    if (iter_type == 4) { // ITER_UBUF
        user_buf = BPF_CORE_READ(msg, msg_iter.ubuf);
    } else {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (iov) {
            user_buf = BPF_CORE_READ(iov, iov_base);
        }
    }
    if (!user_buf) return 0;

    char raw_qname[128];
    bpf_probe_read_user(raw_qname, sizeof(raw_qname), (char *)user_buf + 12);

    uint64_t qname_hash = 0;
    bpf_probe_read_kernel(&qname_hash, sizeof(qname_hash), raw_qname);
    if (qname_hash != 0) {
        uint64_t *cached = bpf_map_lookup_elem(&dns_cache_map, &qname_hash);
        if (cached) {
            return 0; // already seen, exit early!
        }
        uint64_t ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&dns_cache_map, &qname_hash, &ts, BPF_ANY);
    }

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 21, SRC_BPF_LSM, pid); // EVT_DNS_QUERY = 21
        bpf_probe_read_kernel(event->details.details_buffer, 128, raw_qname);

        uint16_t dport_be = bpf_htons(dest_port);
        bpf_probe_read_kernel(event->details.details_buffer + 174, 2, &dport_be);

        if (family == 2) {
            struct sockaddr_in sin;
            bpf_probe_read_kernel(&sin, sizeof(sin), address);
            uint32_t src_ip = sin.sin_addr.s_addr;
            unsigned char *b = (unsigned char *)&src_ip;
            event->details.details_buffer[128] = 0x04;
            event->details.details_buffer[129] = b[0];
            event->details.details_buffer[130] = b[1];
            event->details.details_buffer[131] = b[2];
            event->details.details_buffer[132] = b[3];
            event->details.details_buffer[133] = 0;
        } else if (family == 10) {
            struct sockaddr_in6 sin6;
            bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
            event->details.details_buffer[128] = 0x06;
            bpf_probe_read_kernel(event->details.details_buffer + 129, 16, &sin6.sin6_addr);
            event->details.details_buffer[145] = 0;
        }
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            bpf_probe_read_user(buf->path, sizeof(buf->path), (char *)user_buf + 12);
            record_and_batch_event(8, NULL, 0, buf->path); // 8 = DNS_QUERY
        }
    }

    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry) {
    if (!dentry) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct process_key key = get_current_process_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 22, SRC_BPF_LSM, pid); // EVT_FILE_DELETE = 22
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(event->details.details_buffer, 512, d_name.name);
        bpf_ringbuf_submit(event, 0);
    }

    if (is_install_session() || is_admin_session()) {
        uint32_t zero = 0;
        struct scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);
        if (buf) {
            struct inode *inode = BPF_CORE_READ(dentry, d_inode);
            uint64_t ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            bpf_probe_read_kernel_str(buf->path, sizeof(buf->path), d_name.name);
            record_and_batch_event(3, NULL, ino, buf->path); // 3 = DELETE
        }
    }

    return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new_cred, const struct cred *old_cred, int flags) {
    if (!new_cred || !old_cred) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct process_key key = get_current_process_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    uint32_t new_uid = BPF_CORE_READ(new_cred, uid.val);
    uint32_t old_uid = BPF_CORE_READ(old_cred, uid.val);

    if (new_uid != old_uid) {
        struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
        if (event) {
            fill_header(event, 24, SRC_BPF_LSM, pid); // EVT_PRIVILEGE_CHANGE = 24
            bpf_probe_read_kernel(event->details.details_buffer, 4, &old_uid);
            bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &new_uid);
            bpf_ringbuf_submit(event, 0);
        }
    }
    return 0;
}

SEC("lsm/shm_shmat")
int BPF_PROG(shm_shmat, struct shmid_kernel *shp, char *shmaddr, int shmflg) {
    if (!shp) return 0;
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct process_key key = get_current_process_key();
    uint32_t *threshold = bpf_map_lookup_elem(&process_threshold_map, &key);
    if (!threshold) return 0;

    int32_t shmid = BPF_CORE_READ(shp, shm_perm.id);
    uint32_t creator_uid = BPF_CORE_READ(shp, shm_perm.cuid.val);

    struct TelemetryEvent *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct TelemetryEvent), 0);
    if (event) {
        fill_header(event, 25, SRC_BPF_LSM, pid); // EVT_IPC_ACCESS = 25
        bpf_probe_read_kernel(event->details.details_buffer, 4, &shmid);
        bpf_probe_read_kernel(event->details.details_buffer + 4, 4, &creator_uid);
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

