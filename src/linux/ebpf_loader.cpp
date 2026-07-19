#include "ebpf_loader.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>

// Custom matching key matching ebpf structure
struct process_key {
    uint32_t pid;
    uint64_t start_time;
};

namespace kinnector::lnx {

static struct bpf_link* AttachOrUpdatePinnedLink(struct bpf_object* bpf_obj, const char* prog_name, const char* pin_path) {
    struct bpf_program* prog = bpf_object__find_program_by_name(bpf_obj, prog_name);
    if (!prog) return nullptr;

    struct bpf_link* link = nullptr;
    if (access(pin_path, F_OK) == 0) {
        link = bpf_link__open(pin_path);
        if (link) {
            int ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog), nullptr);
            if (ret == 0) {
                std::cout << "[BPF Link] Successfully updated pinned link in-place: " << pin_path << std::endl;
                return link;
            }
            std::cerr << "[BPF Link] Failed to update pinned link in-place: " << pin_path << ". Re-creating." << std::endl;
            bpf_link__destroy(link);
            unlink(pin_path);
        }
    }

    link = bpf_program__attach(prog);
    if (link) {
        int ret = bpf_link__pin(link, pin_path);
        if (ret == 0) {
            std::cout << "[BPF Link] Successfully attached and pinned: " << pin_path << std::endl;
        } else {
            std::cerr << "[BPF Link] Failed to pin link to " << pin_path << ": " << std::strerror(-ret) << std::endl;
        }
    }
    return link;
}

EbpfLoader::EbpfLoader() = default;

EbpfLoader::~EbpfLoader() {
    Stop();
}

bool EbpfLoader::CheckLsmSupport() {
    std::ifstream lsm_file("/sys/kernel/security/lsm");
    if (!lsm_file.is_open()) {
        return false;
    }
    std::string lsm_list;
    std::getline(lsm_file, lsm_list);
    return lsm_list.find("bpf") != std::string::npos;
}

bool EbpfLoader::Initialize(const std::string& bpf_obj_path, bool force_fallback) {
    if (initialized_) {
        return false;
    }
    bpf_obj_path_ = bpf_obj_path;

    // Check if the eBPF object file exists
    if (access(bpf_obj_path_.c_str(), F_OK) == -1) {
        std::cerr << "eBPF object file not found at: " << bpf_obj_path_ << ". Bypassing to mock mode." << std::endl;
        mock_mode_ = true;
        lsm_active_ = false;
        initialized_ = true;
        return true;
    }

    if (force_fallback) {
        std::cout << "Force fallback mode requested." << std::endl;
        lsm_active_ = false;
    } else {
        lsm_active_ = CheckLsmSupport();
        if (!lsm_active_) {
            std::cout << "BPF LSM not active in kernel. Configuring fallback tracepoint mode." << std::endl;
        }
    }

    initialized_ = true;
    return true;
}

bool EbpfLoader::Start() {
    if (!initialized_ || running_) {
        return false;
    }

    if (mock_mode_) {
        std::cout << "Running in mock telemetry mode (offline/user-space verification)." << std::endl;
        running_ = true;
        return true;
    }

    running_ = true;

    if (lsm_active_) {
        if (!LoadAndAttachLsm()) {
            std::cerr << "Failed to load/attach BPF LSM. Falling back to tracepoint mode." << std::endl;
            lsm_active_ = false;
            if (!LoadAndAttachFallback()) {
                std::cerr << "Fallback tracepoint attachment failed." << std::endl;
                running_ = false;
                return false;
            }
        }
    } else {
        if (!LoadAndAttachFallback()) {
            std::cerr << "Fallback tracepoint attachment failed." << std::endl;
            running_ = false;
            return false;
        }
    }

    // Set up ring buffer polling loop if the bpf object has been loaded
    if (bpf_obj_) {
        ring_buf_ = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(bpf_obj_, "telemetry_ringbuf")),
                                     HandleRingBufferEvent, this, nullptr);
        if (!ring_buf_) {
            std::cerr << "Failed to initialize telemetry ring buffer." << std::endl;
            Stop();
            return false;
        }

        // Add tty_ringbuf to the same manager (P8-pty)
        struct bpf_map* tty_map = bpf_object__find_map_by_name(bpf_obj_, "tty_ringbuf");
        if (tty_map) {
            int tty_fd = bpf_map__fd(tty_map);
            if (ring_buffer__add(ring_buf_, tty_fd, HandleTtyRingBufferEvent, this) != 0) {
                std::cerr << "Warning: Failed to add tty_ringbuf to ring buffer manager." << std::endl;
            }
        }

        // Attach TTY/PTY hooks with pinning for zero-downtime hot-reloading
        mkdir("/sys/fs/bpf", 0755);
        mkdir("/sys/fs/bpf/warden", 0755);

        kprobe_tty_write_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "kprobe_tty_write", "/sys/fs/bpf/warden/kprobe_tty_write");
        kprobe_tty_read_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "kprobe_tty_read", "/sys/fs/bpf/warden/kprobe_tty_read");
        kretprobe_tty_read_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "kretprobe_tty_read", "/sys/fs/bpf/warden/kretprobe_tty_read");

        ring_buffer_thread_ = std::thread(&EbpfLoader::RingBufferPollLoop, this);
    }

    return true;
}

void EbpfLoader::Stop() {
    running_ = false;
    
    if (ring_buffer_thread_.joinable()) {
        ring_buffer_thread_.join();
    }
    
    if (ring_buf_) {
        ring_buffer__free(ring_buf_);
        ring_buf_ = nullptr;
    }
    
    // For pinned links: disconnect them so they persist in the kernel, then destroy the structure
    auto CleanPinnedLink = [](struct bpf_link*& link) {
        if (link) {
            bpf_link__disconnect(link);
            bpf_link__destroy(link);
            link = nullptr;
        }
    };

    CleanPinnedLink(file_open_link_);
    CleanPinnedLink(socket_connect_link_);
    CleanPinnedLink(socket_listen_link_);
    CleanPinnedLink(exec_link_);
    CleanPinnedLink(bprm_check_security_link_);
    CleanPinnedLink(ptrace_link_);
    CleanPinnedLink(kprobe_tty_write_link_);
    CleanPinnedLink(kprobe_tty_read_link_);
    CleanPinnedLink(kretprobe_tty_read_link_);
    CleanPinnedLink(mprotect_link_);
    CleanPinnedLink(task_kill_link_);
    CleanPinnedLink(path_chmod_link_);

    // Fallback tracepoints are not pinned, so we can destroy them normally
    if (tp_exec_link_)         { bpf_link__destroy(tp_exec_link_); tp_exec_link_ = nullptr; }
    if (tp_connect_link_)      { bpf_link__destroy(tp_connect_link_); tp_connect_link_ = nullptr; }
    if (tp_exit_link_)         { bpf_link__destroy(tp_exit_link_); tp_exit_link_ = nullptr; }
    if (tp_openat_link_)       { bpf_link__destroy(tp_openat_link_); tp_openat_link_ = nullptr; }
    if (tp_mmap_link_)         { bpf_link__destroy(tp_mmap_link_); tp_mmap_link_ = nullptr; }
    if (tp_mprotect_link_)     { bpf_link__destroy(tp_mprotect_link_); tp_mprotect_link_ = nullptr; }
    if (tp_dup2_link_)         { bpf_link__destroy(tp_dup2_link_); tp_dup2_link_ = nullptr; }
    if (tp_dup3_link_)         { bpf_link__destroy(tp_dup3_link_); tp_dup3_link_ = nullptr; }
    if (tp_listen_link_)       { bpf_link__destroy(tp_listen_link_); tp_listen_link_ = nullptr; }


    file_open_link_      = nullptr;
    socket_connect_link_ = nullptr;
    socket_listen_link_  = nullptr;
    exec_link_           = nullptr;
    bprm_check_security_link_ = nullptr;
    ptrace_link_         = nullptr;
    kprobe_tty_write_link_ = nullptr;
    kprobe_tty_read_link_  = nullptr;
    kretprobe_tty_read_link_ = nullptr;
    mprotect_link_       = nullptr;
    task_kill_link_      = nullptr;
    path_chmod_link_     = nullptr;
    tp_exec_link_        = nullptr;
    tp_connect_link_     = nullptr;
    tp_exit_link_        = nullptr;
    tp_openat_link_      = nullptr;
    tp_mmap_link_        = nullptr;
    tp_mprotect_link_    = nullptr;
    tp_dup2_link_        = nullptr;
    tp_dup3_link_        = nullptr;
    tp_listen_link_      = nullptr;

    if (bpf_obj_) {
        bpf_object__close(bpf_obj_);
        bpf_obj_ = nullptr;
    }

    initialized_ = false;
}

static void ApplyRamBasedMapScaling(struct bpf_object* bpf_obj) {
    if (!bpf_obj) return;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    uint64_t total_ram_bytes = (uint64_t)pages * (uint64_t)page_size;

    uint32_t auto_max_entries = 65536;
    if (total_ram_bytes < 4ULL * 1024 * 1024 * 1024) {          // < 4 GB
        auto_max_entries = 16384;
    } else if (total_ram_bytes < 8ULL * 1024 * 1024 * 1024) {   // 4 GB - 8 GB
        auto_max_entries = 32768;
    } else if (total_ram_bytes < 16ULL * 1024 * 1024 * 1024) {  // 8 GB - 16 GB
        auto_max_entries = 65536;
    } else if (total_ram_bytes < 24ULL * 1024 * 1024 * 1024) {  // 16 GB - 24 GB
        auto_max_entries = 131072;
    } else if (total_ram_bytes < 32ULL * 1024 * 1024 * 1024) {  // 24 GB - 32 GB
        auto_max_entries = 196608;
    } else if (total_ram_bytes < 48ULL * 1024 * 1024 * 1024) {  // 32 GB - 48 GB
        auto_max_entries = 262144;
    } else if (total_ram_bytes < 64ULL * 1024 * 1024 * 1024) {  // 48 GB - 64 GB
        auto_max_entries = 524288;
    } else {                                                     // >= 64 GB
        auto_max_entries = 1048576;
    }

    const char* maps_to_scale[] = {
        "process_threshold_map",
        "category_flags_map",
        "pending_network_connect",
        "sensitive_inodes_map",
        "trusted_exec_inodes",
        "exec_allowlist_map",
        "tainted_process_map",
        "pid_tree_type_map",
        "db_outbound_allowlist",
        "infra_outbound_allowlist"
    };

    for (const char* map_name : maps_to_scale) {
        struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj, map_name);
        if (map) {
            bpf_map__set_max_entries(map, auto_max_entries);
        }
    }
}

bool EbpfLoader::LoadAndAttachLsm() {
    bpf_obj_ = bpf_object__open_file(bpf_obj_path_.c_str(), nullptr);
    if (!bpf_obj_) {
        return false;
    }

    // Apply RAM-based pre-allocated map sizing before load
    ApplyRamBasedMapScaling(bpf_obj_);

    // Set BPF program types dynamically to LSM
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, bpf_obj_) {
        const char* sec_name = bpf_program__section_name(prog);
        if (sec_name && std::strncmp(sec_name, "lsm/", 4) == 0) {
            bpf_program__set_type(prog, BPF_PROG_TYPE_LSM);
            bpf_program__set_expected_attach_type(prog, BPF_LSM_MAC);
        }
    }

    if (bpf_object__load(bpf_obj_) != 0) {
        bpf_object__close(bpf_obj_);
        bpf_obj_ = nullptr;
        return false;
    }

    // Attach LSM hooks with pinning for zero-downtime hot-reloading
    mkdir("/sys/fs/bpf", 0755);
    mkdir("/sys/fs/bpf/warden", 0755);

    file_open_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "file_open", "/sys/fs/bpf/warden/file_open");
    socket_connect_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "socket_connect", "/sys/fs/bpf/warden/socket_connect");
    socket_listen_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "socket_listen", "/sys/fs/bpf/warden/socket_listen");
    exec_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "bprm_creds_for_exec", "/sys/fs/bpf/warden/bprm_creds_for_exec");
    bprm_check_security_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "bprm_check_security", "/sys/fs/bpf/warden/bprm_check_security");
    ptrace_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "ptrace_access_check", "/sys/fs/bpf/warden/ptrace_access_check");
    mprotect_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "file_mprotect", "/sys/fs/bpf/warden/file_mprotect");
    task_kill_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "task_kill", "/sys/fs/bpf/warden/task_kill");
    path_chmod_link_ = AttachOrUpdatePinnedLink(bpf_obj_, "path_chmod", "/sys/fs/bpf/warden/path_chmod");

    // P2-8: Attach file_permission for FileWrite events
    AttachOrUpdatePinnedLink(bpf_obj_, "file_permission", "/sys/fs/bpf/warden/file_permission");

    // Attach new Dimension 5 telemetry hooks
    AttachOrUpdatePinnedLink(bpf_obj_, "socket_post_accept", "/sys/fs/bpf/warden/socket_post_accept");
    AttachOrUpdatePinnedLink(bpf_obj_, "socket_sendmsg", "/sys/fs/bpf/warden/socket_sendmsg");
    AttachOrUpdatePinnedLink(bpf_obj_, "inode_unlink", "/sys/fs/bpf/warden/inode_unlink");
    AttachOrUpdatePinnedLink(bpf_obj_, "task_fix_setuid", "/sys/fs/bpf/warden/task_fix_setuid");
    AttachOrUpdatePinnedLink(bpf_obj_, "shm_shmat", "/sys/fs/bpf/warden/shm_shmat");

    // Q-06 fix: validate exec_link_ is attached before reporting success
    return file_open_link_ && socket_connect_link_ && exec_link_ && bprm_check_security_link_;
}

bool EbpfLoader::LoadAndAttachFallback() {
    bpf_obj_ = bpf_object__open_file(bpf_obj_path_.c_str(), nullptr);
    if (!bpf_obj_) {
        return false;
    }

    // Apply RAM-based pre-allocated map sizing before load
    ApplyRamBasedMapScaling(bpf_obj_);

    // Unload LSM programs (since we are in fallback, they would fail to load)
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, bpf_obj_) {
        const char* sec_name = bpf_program__section_name(prog);
        if (sec_name && std::strncmp(sec_name, "lsm/", 4) == 0) {
            bpf_program__set_autoload(prog, false);
        }
    }

    if (bpf_object__load(bpf_obj_) != 0) {
        bpf_object__close(bpf_obj_);
        bpf_obj_ = nullptr;
        return false;
    }

    // P2-13: Attach all new tracepoint programs for fallback mode
    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_execve");
    if (prog) tp_exec_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_connect");
    if (prog) tp_connect_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sched_process_exit");
    if (prog) tp_exit_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_openat");
    if (prog) tp_openat_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_mmap");
    if (prog) tp_mmap_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_mprotect");
    if (prog) tp_mprotect_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_dup2");
    if (prog) tp_dup2_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_dup3");
    if (prog) tp_dup3_link_ = bpf_program__attach(prog);

    prog = bpf_object__find_program_by_name(bpf_obj_, "tracepoint_sys_enter_listen");
    if (prog) tp_listen_link_ = bpf_program__attach(prog);

    return tp_exec_link_ != nullptr;

}

bool EbpfLoader::UpdateMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time, uint32_t value) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    const char* map_name = nullptr;
    switch (map_type) {
        case BpfMapType::CategoryFlags: map_name = "category_flags_map"; break;
        case BpfMapType::PendingNetwork: map_name = "pending_network_connect"; break;
        case BpfMapType::TrustedRoots: map_name = "trusted_ancestor_roots"; break;
        case BpfMapType::TaintedProcess: map_name = "tainted_process_map"; break;
        case BpfMapType::ProcessThreshold: map_name = "process_threshold_map"; break;
        case BpfMapType::PidTreeType: map_name = "pid_tree_type_map"; break;
        case BpfMapType::JvmExceptionPids: map_name = "jvm_exception_pids"; break;
        case BpfMapType::DbOutboundAllowlist: map_name = "db_outbound_allowlist"; break;
        case BpfMapType::InfraOutboundAllowlist: map_name = "infra_outbound_allowlist"; break;
        case BpfMapType::ExecAllowlistMap: map_name = "exec_allowlist_map"; break;
        case BpfMapType::AdminSessionPids: map_name = "admin_session_pids"; break;
        case BpfMapType::TrustedAdminBinaries: map_name = "trusted_admin_binaries"; break;
        default: return false;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, map_name);
    if (!map) return false;

    int fd = bpf_map__fd(map);
    
    // For maps that key on pid (uint32_t) rather than process_key
    if (map_type == BpfMapType::PidTreeType) {
        uint32_t val = value;
        return bpf_map_update_elem(fd, &pid, &val, BPF_ANY) == 0;
    } else if (map_type == BpfMapType::JvmExceptionPids || map_type == BpfMapType::AdminSessionPids) {
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &pid, &val8, BPF_ANY) == 0;
    } else if (map_type == BpfMapType::DbOutboundAllowlist || map_type == BpfMapType::InfraOutboundAllowlist) {
        struct {
            uint32_t pid;
            uint32_t ip;
        } __attribute__((packed)) key = { pid, static_cast<uint32_t>(start_time) };
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &key, &val8, BPF_ANY) == 0;
    } else if (map_type == BpfMapType::ExecAllowlistMap || map_type == BpfMapType::TrustedAdminBinaries) {
        uint64_t key = start_time;
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &key, &val8, BPF_ANY) == 0;
    }

    struct process_key key = { pid, start_time };
    
    // For TrustedRoots, map holds uint8_t, others hold uint32_t
    if (map_type == BpfMapType::TrustedRoots) {
        uint8_t val8 = static_cast<uint8_t>(value);
        return bpf_map_update_elem(fd, &key, &val8, BPF_ANY) == 0;
    } else {
        return bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0;
    }
}

bool EbpfLoader::DeleteMapEntry(BpfMapType map_type, uint32_t pid, uint64_t start_time) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    const char* map_name = nullptr;
    switch (map_type) {
        case BpfMapType::CategoryFlags: map_name = "category_flags_map"; break;
        case BpfMapType::PendingNetwork: map_name = "pending_network_connect"; break;
        case BpfMapType::TrustedRoots: map_name = "trusted_ancestor_roots"; break;
        case BpfMapType::TaintedProcess: map_name = "tainted_process_map"; break;
        case BpfMapType::ProcessThreshold: map_name = "process_threshold_map"; break;
        case BpfMapType::PidTreeType: map_name = "pid_tree_type_map"; break;
        case BpfMapType::JvmExceptionPids: map_name = "jvm_exception_pids"; break;
        case BpfMapType::DbOutboundAllowlist: map_name = "db_outbound_allowlist"; break;
        case BpfMapType::InfraOutboundAllowlist: map_name = "infra_outbound_allowlist"; break;
        case BpfMapType::ExecAllowlistMap: map_name = "exec_allowlist_map"; break;
        case BpfMapType::AdminSessionPids: map_name = "admin_session_pids"; break;
        case BpfMapType::TrustedAdminBinaries: map_name = "trusted_admin_binaries"; break;
        default: return false;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, map_name);
    if (!map) return false;

    int fd = bpf_map__fd(map);
    if (map_type == BpfMapType::PidTreeType || map_type == BpfMapType::JvmExceptionPids || map_type == BpfMapType::AdminSessionPids) {
        return bpf_map_delete_elem(fd, &pid) == 0;
    } else if (map_type == BpfMapType::DbOutboundAllowlist || map_type == BpfMapType::InfraOutboundAllowlist) {
        struct {
            uint32_t pid;
            uint32_t ip;
        } __attribute__((packed)) key = { pid, static_cast<uint32_t>(start_time) };
        return bpf_map_delete_elem(fd, &key) == 0;
    } else if (map_type == BpfMapType::ExecAllowlistMap || map_type == BpfMapType::TrustedAdminBinaries) {
        uint64_t key = start_time;
        return bpf_map_delete_elem(fd, &key) == 0;
    } else {
        struct process_key key = { pid, start_time };
        return bpf_map_delete_elem(fd, &key) == 0;
    }
}

bool EbpfLoader::AddSensitiveInode(uint64_t inode, uint32_t category) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "sensitive_inodes_map");
    if (!map) return false;

    return bpf_map_update_elem(bpf_map__fd(map), &inode, &category, BPF_ANY) == 0;
}

bool EbpfLoader::AddProtectedStaticInode(uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "protected_static_inodes");
    if (!map) return false;

    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &inode, &val, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveProtectedStaticInode(uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "protected_static_inodes");
    if (!map) return false;

    return bpf_map_delete_elem(bpf_map__fd(map), &inode) == 0;
}

bool EbpfLoader::AddTrustedExecInode(uint64_t inode, uint32_t trust_level) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "trusted_exec_inodes");
    if (!map) return false;

    return bpf_map_update_elem(bpf_map__fd(map), &inode, &trust_level, BPF_ANY) == 0;
}

bool EbpfLoader::LookupTrustedExecInode(uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        // In mock mode, treat everything as trusted to avoid false positives
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "trusted_exec_inodes");
    if (!map) return false;

    uint32_t trust_level = 0;
    return bpf_map_lookup_elem(bpf_map__fd(map), &inode, &trust_level) == 0;
}

bool EbpfLoader::SetConfigValue(uint32_t index, uint32_t value) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "config_map");
    if (!map) return false;

    return bpf_map_update_elem(bpf_map__fd(map), &index, &value, BPF_ANY) == 0;
}

bool EbpfLoader::AddBypassedDirectoryInode(uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "bypassed_directories");
    if (!map) return false;

    uint8_t val = 1;
    return bpf_map_update_elem(bpf_map__fd(map), &inode, &val, BPF_ANY) == 0;
}

bool EbpfLoader::RemoveBypassedDirectoryInode(uint64_t inode) {
    if (mock_mode_ || !bpf_obj_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj_, "bypassed_directories");
    if (!map) return false;

    return bpf_map_delete_elem(bpf_map__fd(map), &inode) == 0;
}


void EbpfLoader::SetTtyEventCallback(TtyEventCallback cb) {
    tty_event_callback_ = cb;
}

void EbpfLoader::SetEventCallback(EventCallback cb) {
    event_callback_ = cb;
}

void EbpfLoader::RingBufferPollLoop() {
    while (running_) {
        int err = ring_buffer__poll(ring_buf_, 100);
        if (err < 0 && err != -EINTR) {
            std::cerr << "Error polling eBPF ring buffer" << std::endl;
            break;
        }
    }
}

int EbpfLoader::HandleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
    auto* loader = static_cast<EbpfLoader*>(ctx);
    std::cout << "[EbpfLoader] Received event from ring buffer. Size: " << data_sz 
              << ", Expected: " << sizeof(TelemetryEvent) << std::endl;
    if (loader->event_callback_ && data && data_sz == sizeof(TelemetryEvent)) {
        loader->event_callback_(*static_cast<TelemetryEvent*>(data));
    }
    return 0;
}

int EbpfLoader::HandleTtyRingBufferEvent(void *ctx, void *data, size_t data_sz) {
    auto* loader = static_cast<EbpfLoader*>(ctx);
    std::cout << "[EbpfLoader] Received TTY event from ring buffer. Size: " << data_sz 
              << ", Expected: " << sizeof(TtyEvent) << std::endl;
    if (loader->tty_event_callback_ && data && data_sz == sizeof(TtyEvent)) {
        loader->tty_event_callback_(*static_cast<TtyEvent*>(data));
    }
    return 0;
}

} // namespace kinnector::lnx
