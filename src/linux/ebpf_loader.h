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
    ConfigMap
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
    bool AddSensitiveInode(uint64_t inode, uint32_t category);
    bool AddTrustedExecInode(uint64_t inode, uint32_t trust_level);
    // Fix 10: query whether an inode is present in the trusted_exec_inodes BPF map
    bool LookupTrustedExecInode(uint64_t inode);
    bool SetConfigValue(uint32_t index, uint32_t value);

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
    struct bpf_link* ptrace_link_{nullptr};
    struct bpf_link* mprotect_link_{nullptr};

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
