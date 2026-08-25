#ifndef KINNECTOR_EBPF_LOADER_H
#define KINNECTOR_EBPF_LOADER_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <thread>
#include <atomic>
#include "kinnector/telemetry.h"

// Forward declarations for libbpf types to avoid exposing headers globally
struct bpf_object;
struct bpf_link;
struct ring_buffer;

namespace kinnector::lnx {

// Map types for core-agent communication
enum class BpfMapType {
    CategoryFlags,
    PendingNetwork,
    TrustedRoots,
    SensitiveInodes,
    TaintedProcess,
    TrustedExecInodes,
    ProcessThreshold,
    ConfigMap,
    BypassedDirectories,
    PidTreeType,
    JvmExceptionPids,
    DbOutboundAllowlist,
    InfraOutboundAllowlist,
    ExecAllowlistMap,
    AdminSessionPids,
    TrustedAdminBinaries,
    // Phase 4 (LINUX_COVERAGE_PLAN.md): resolved package-manager binary inode -> 1.
    // Populated via UpdateMapEntry(InstallBinaryMap, /*pid unused*/0, inode, 1), same
    // start_time-as-key convention already used for ExecAllowlistMap/TrustedAdminBinaries.
    InstallBinaryMap,
    // Phase 5: configured owner-protection binary inode -> 1 (e.g. a password
    // manager). Same start_time-as-key convention as InstallBinaryMap.
    ProtectedOwnerBinaries,
    // Phase 5: (pid, start_time) -> 1, stamped by the kernel at exec time when a
    // process matches ProtectedOwnerBinaries -- read-only from userspace's
    // perspective in the common case, but exposed via the normal
    // UpdateMapEntry/DeleteMapEntry process_key path for test/debug use.
    ProtectedOwnerPids
};

class EbpfLoader {
public:
    EbpfLoader();
    ~EbpfLoader();

    // Initializes loader, checks capabilities, and sets up fallback status
    bool Initialize(const std::string& bpf_obj_path, bool force_fallback = false);

    // Starts loading and attaching eBPF programs (or sets up mock mode)
    bool Start();

    // Detaches and unloads eBPF programs
    void Stop();

    // Map modification interfaces
    bool UpdateMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time, uint32_t value);
    bool DeleteMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time);
    // Phase 6 (LINUX_COVERAGE_PLAN.md): sensitive/protected-*file*-identity maps
    // (sensitive, protected-static, resource-owner, bypassed-directory) take a
    // `dev` (st_dev/dev_t, widened) alongside `inode` -- a bare inode number is
    // ambiguous across bind-mounts/multiple filesystems with overlapping inode
    // ranges. Deliberately NOT applied to the exec-trust/binary-identity
    // functions below (AddTrustedExecInode etc.) -- see kinnector.bpf.c's
    // resource_id declaration comment for the scoping rationale.
    bool AddSensitiveInode(uint64_t dev, uint64_t inode, uint32_t category);
    bool AddProtectedStaticInode(uint64_t dev, uint64_t inode);
    bool RemoveProtectedStaticInode(uint64_t dev, uint64_t inode);
    bool AddTrustedExecInode(uint64_t inode, uint32_t trust_level);
    // Fix 10: query whether an inode is present in the trusted_exec_inodes BPF map
    bool LookupTrustedExecInode(uint64_t inode);
    bool SetConfigValue(uint32_t index, uint32_t value);
    // DB: register a directory inode in the bypassed_directories bypass map
    bool AddBypassedDirectoryInode(uint64_t dev, uint64_t inode);
    // DB: remove a directory inode from bypassed_directories (on DB process stop)
    bool RemoveBypassedDirectoryInode(uint64_t dev, uint64_t inode);

    // Phase 3 (LINUX_COVERAGE_PLAN.md): register/unregister `owner_exec_inode` as a
    // legitimate owner process for the protected resource `(resource_dev,
    // resource_inode)`, via the same 64-slot hash-bitmask representation
    // kinnector.bpf.c's resource_owner_hash() uses -- this is Antitheft-only;
    // callers must have already set CONFIG_DEPLOYMENT_MODE == MODE_ANTITHEFT via
    // SetConfigValue for the kernel side to ever consult this map.
    // `owner_exec_inode` itself stays a bare inode (Phase 6 scope is the
    // protected *resource*'s identity, not the lossy owner-hash bucket input).
    bool AddResourceOwner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);
    bool RemoveResourceOwner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);

    // Firewall (warden/src/firewall) — one CIDR at a time; the caller
    // (warden's EbpfBackend) owns the desired-state diff and issues a call
    // per added/removed CIDR, so no bulk/array variant is needed here — see
    // fw_key4/fw_key6/fw_value in kinnector.bpf.c for the wire shape.
    // `addr` must point to 4 bytes (is_v6=false) or 16 bytes (is_v6=true),
    // network byte order. `prefixlen` is in bits.
    bool AddFirewallCidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                          uint32_t rule_id, uint16_t port, uint8_t proto,
                          uint8_t direction, uint8_t action);
    bool RemoveFirewallCidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen);
    // Anti-tamper: total live entry count across both firewall tries, for
    // ebpf_health.rs to compare against warden's own expected count.
    // Returns -1 if the maps aren't reachable (mock mode / not loaded).
    int64_t CountFirewallEntries();

    // Checks if the active mode is BPF LSM or Fallback (Tracepoints)
    bool IsLsmActive() const { return lsm_active_; }
    bool IsMockMode() const { return mock_mode_; }

    struct TtyEvent {
        uint64_t timestamp_ns;
        uint32_t pid;
        uint32_t len;
        uint8_t  is_write;
        char     comm[16];
        char     data[1024];
    } __attribute__((packed));

    // Read events from the BPF ring buffer (non-blocking)
    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

    using TtyEventCallback = std::function<void(const TtyEvent&)>;
    void SetTtyEventCallback(TtyEventCallback cb);

private:
    bool CheckLsmSupport();
    bool LoadAndAttachLsm();
    bool LoadAndAttachFallback();
    void RingBufferPollLoop();
    static int HandleRingBufferEvent(void *ctx, void *data, size_t data_sz);
    static int HandleTtyRingBufferEvent(void *ctx, void *data, size_t data_sz);

    std::string bpf_obj_path_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> lsm_active_{false};
    std::atomic<bool> mock_mode_{false};
    
    struct bpf_object* bpf_obj_{nullptr};
    struct bpf_link* file_open_link_{nullptr};
    struct bpf_link* socket_connect_link_{nullptr};
    struct bpf_link* socket_listen_link_{nullptr};
    struct bpf_link* exec_link_{nullptr};
    struct bpf_link* bprm_check_security_link_{nullptr};
    struct bpf_link* ptrace_link_{nullptr};
    struct bpf_link* mprotect_link_{nullptr};
    struct bpf_link* task_kill_link_{nullptr};
    struct bpf_link* path_chmod_link_{nullptr};
    struct bpf_link* mmap_file_link_{nullptr};   // image-load telemetry + W^X block (LSM-mode only)
    struct bpf_link* fork_link_{nullptr};        // sched_process_fork, pinned LSM-mode attach — lineage propagation

    // Fallback tracepoint links
    struct bpf_link* tp_exec_link_{nullptr};
    struct bpf_link* tp_connect_link_{nullptr};
    struct bpf_link* tp_exit_link_{nullptr};     // sched_process_exit → ProcessStop
    struct bpf_link* tp_openat_link_{nullptr};   // sys_enter_openat → FileOpen
    struct bpf_link* tp_mmap_link_{nullptr};     // sys_enter_mmap → MemoryMap
    struct bpf_link* tp_mprotect_link_{nullptr}; // sys_enter_mprotect → MemoryMap
    struct bpf_link* tp_dup2_link_{nullptr};     // sys_enter_dup2 → Dup2
    struct bpf_link* tp_dup3_link_{nullptr};     // sys_enter_dup3 → Dup2
    struct bpf_link* tp_listen_link_{nullptr};   // sys_enter_listen → Listen
    struct bpf_link* tp_fork_link_{nullptr};     // sched_process_fork, fallback-mode attach — lineage propagation


    // TTY hooks
    struct bpf_link* kprobe_tty_write_link_{nullptr};
    struct bpf_link* kprobe_tty_read_link_{nullptr};
    struct bpf_link* kretprobe_tty_read_link_{nullptr};

    // Ring buffer manager
    struct ring_buffer* ring_buf_{nullptr};
    std::thread ring_buffer_thread_;
    std::mutex map_mutex_;
    EventCallback event_callback_;
    TtyEventCallback tty_event_callback_;
};

} // namespace kinnector::lnx

#endif // KINNECTOR_EBPF_LOADER_H
