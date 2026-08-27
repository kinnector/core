#include "kinnector/ffi.h"
#include "kinnector/ipc.h"

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#if defined(TARGET_OS_LINUX)
#include "linux/ebpf_loader.h"
#include "linux/fanotify.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <atomic>

class LinuxTtyTelemetrySender {
public:
    LinuxTtyTelemetrySender() = default;
    ~LinuxTtyTelemetrySender() { Stop(); }

    bool Start(const std::string& path) {
        if (running_) return false;
        socket_path_ = path;
        running_ = true;
        connection_thread_ = std::thread(&LinuxTtyTelemetrySender::ConnectionLoop, this);
        return true;
    }

    void Stop() {
        running_ = false;
        connected_ = false;
        int fd = socket_fd_.exchange(-1);
        if (fd != -1) close(fd);
        if (connection_thread_.joinable()) connection_thread_.join();
    }

    bool SendTtyEvent(const kinnector::lnx::EbpfLoader::TtyEvent& event) {
        if (!connected_) return false;
        std::lock_guard<std::mutex> lock(send_mutex_);
        int fd = socket_fd_.load();
        if (fd == -1) return false;
        ssize_t written = write(fd, &event, sizeof(event));
        if (written != sizeof(event)) {
            connected_ = false;
            close(fd);
            socket_fd_ = -1;
            return false;
        }
        return true;
    }

private:
    void ConnectionLoop() {
        while (running_) {
            if (connected_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            struct sockaddr_un addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
            if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(fd);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            socket_fd_ = fd;
            connected_ = true;
        }
    }

    std::string socket_path_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<int> socket_fd_{-1};
    std::thread connection_thread_;
    std::mutex send_mutex_;
};

static LinuxTtyTelemetrySender g_tty_sender;
#endif

#include <memory>
#include <mutex>
#include <iostream>

static std::unique_ptr<kinnector::ipc::ITelemetrySender> g_sender = nullptr;
static kinnector::ipc::IPCConfig g_config;

#if defined(TARGET_OS_LINUX)
static std::unique_ptr<kinnector::lnx::EbpfLoader> g_loader = nullptr;
static std::unique_ptr<kinnector::lnx::FanotifyMonitor> g_fanotify = nullptr;
#elif defined(TARGET_OS_WINDOWS)
#include "windows/etw_consumer.h"
#include "windows/driver_helper.h"
#include "windows/clipboard_helper.h"
#include "windows/resource_identity.h"
#include "windows/process_integrity.h"
#include "windows/authenticode.h"
#include "windows/response.h"
#include "windows/file_guard.h"
#include <windows.h>
static std::unique_ptr<kinnector::windows::EtwConsumer> g_etw = nullptr;
static std::unique_ptr<kinnector::windows::DriverHelper> g_driver = nullptr;
static std::unique_ptr<kinnector::windows::ClipboardHelper> g_clipboard = nullptr;
static std::unique_ptr<kinnector::windows::ProtectedResourceStore> g_resource_store = nullptr;
static std::unique_ptr<kinnector::windows::ProtectedRegistryStore> g_registry_store = nullptr;
static std::unique_ptr<kinnector::windows::ProcessIntegrityStore> g_process_integrity = nullptr;
static std::unique_ptr<kinnector::windows::ResponseEngine> g_response = nullptr;
static std::unique_ptr<kinnector::windows::FileGuard> g_file_guard = nullptr;
#endif

static std::mutex g_ffi_mutex;
static bool g_initialized = false;
static bool g_running = false;

#if defined(TARGET_OS_WINDOWS)
// Not part of the C API surface (has C++ linkage, returns std::wstring) -
// deliberately kept outside extern "C" below.
static std::wstring Utf8ToWstrFfi(const char* utf8) {
    if (!utf8 || !utf8[0]) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring result(static_cast<size_t>(n) - 1, L'\0');  // n includes the null terminator
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, result.data(), n);
    return result;
}

static std::string WstrToUtf8Ffi(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string result(static_cast<size_t>(n) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, result.data(), n, nullptr, nullptr);
    return result;
}

// Copy a std::string into a caller buffer, always NUL-terminating (truncating
// if needed). No-op if buf is null or cap is 0.
static void CopyOutStr(const std::string& src, char* buf, size_t cap) {
    if (!buf || cap == 0) return;
    size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    memcpy(buf, src.data(), n);
    buf[n] = '\0';
}

// WS7: the FileGuard break-handler's verdict + response step. Defined lower in
// this file (needs EvaluateActor); forward-declared here so
// initialize_telemetry_engine can hand its address to the FileGuard.
namespace {
kinnector::windows::FileGuard::EnforceResult FileGuardEnforce(
    const std::vector<uint32_t>& candidate_pids, uint32_t volume_serial, uint64_t frn);
}
#endif

extern "C" {

bool initialize_telemetry_engine(const char* bpf_obj_path, const char* socket_path, const char* auth_token) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_initialized) {
        return false;
    }

    g_config.socket_path = socket_path ? socket_path : "";
    g_config.pipe_name = socket_path ? socket_path : "";
    g_config.auth_token = auth_token ? auth_token : "";

    g_sender = kinnector::ipc::CreateTelemetrySender();
    if (!g_sender) {
        return false;
    }

#if defined(TARGET_OS_LINUX)
    g_loader = std::make_unique<kinnector::lnx::EbpfLoader>();
    if (!g_loader || !g_loader->Initialize(bpf_obj_path ? bpf_obj_path : "", false)) {
        g_sender.reset();
        g_loader.reset();
        return false;
    }

    g_fanotify = std::make_unique<kinnector::lnx::FanotifyMonitor>();
    // enable_blocking intentionally omitted (defaults false): this Initialize()
    // call marks the ROOT filesystem. Passing true here would arm FAN_OPEN_PERM
    // mount-wide, blocking every open() on the whole machine on this one
    // monitor thread -- see fanotify.h's Initialize() comment. Never flip this
    // without the per-path-mark follow-up documented there.
    if (!g_fanotify || !g_fanotify->Initialize("/")) {
        std::cerr << "[FFI] Warning: Fanotify FIM failed to initialize. Continuing with eBPF only." << std::endl;
        g_fanotify.reset();
    }
#elif defined(TARGET_OS_WINDOWS)
    g_etw = std::make_unique<kinnector::windows::EtwConsumer>();
    if (!g_etw || !g_etw->Initialize()) {
        g_sender.reset();
        g_etw.reset();
        return false;
    }
    
    g_driver = std::make_unique<kinnector::windows::DriverHelper>();
    if (!g_driver || !g_driver->Initialize()) {
        std::cerr << "[FFI] Warning: Driver Helper failed to initialize. Operating in ETW mode only." << std::endl;
        g_driver.reset();
    }

    g_clipboard = std::make_unique<kinnector::windows::ClipboardHelper>();
    if (!g_clipboard || !g_clipboard->Initialize()) {
        std::cerr << "[FFI] Warning: Clipboard Helper failed to initialize. Continuing without clipboard telemetry." << std::endl;
        g_clipboard.reset();
    }

    // Pure in-memory map, no external dependency to fail against.
    g_resource_store = std::make_unique<kinnector::windows::ProtectedResourceStore>();
    g_registry_store = std::make_unique<kinnector::windows::ProtectedRegistryStore>();
    g_process_integrity = std::make_unique<kinnector::windows::ProcessIntegrityStore>();
    g_response = std::make_unique<kinnector::windows::ResponseEngine>();  // disarmed
    // WS7: oplock hold. Suspension is still gated on g_response's enforcement
    // flag (disarmed by default) - arming a guard only enables correlation.
    g_file_guard = std::make_unique<kinnector::windows::FileGuard>(&FileGuardEnforce);
#endif

    g_initialized = true;
    std::cout << "[FFI] Telemetry Engine initialized successfully." << std::endl;
    return true;
}

bool start_telemetry_engine() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (!g_initialized || g_running) {
        return false;
    }

    // Start the IPC sender
    if (!g_sender->Start(g_config)) {
        std::cerr << "[FFI] Failed to start IPC sender" << std::endl;
        return false;
    }

#if defined(TARGET_OS_LINUX)
    // Start TTY/PTY IPC sender
    g_tty_sender.Start("/var/run/kinnector/tty_telemetry.sock");

    // Forward eBPF events from the ring buffer directly to the agent over the IPC socket
    g_loader->SetEventCallback([](const TelemetryEvent& event) {
        if (g_sender) {
            g_sender->SendEvent(event);
        }
    });

    g_loader->SetTtyEventCallback([](const kinnector::lnx::EbpfLoader::TtyEvent& event) {
        g_tty_sender.SendTtyEvent(event);
    });

    if (!g_loader->Start()) {
        std::cerr << "[FFI] Failed to start EbpfLoader" << std::endl;
        g_tty_sender.Stop();
        g_sender->Stop();
        return false;
    }

    if (g_fanotify) {
        g_fanotify->SetEventCallback([](const TelemetryEvent& event) {
            if (g_sender) {
                g_sender->SendEvent(event);
            }
        });
        if (!g_fanotify->Start()) {
            std::cerr << "[FFI] Warning: Failed to start Fanotify monitor" << std::endl;
        }
    }
#elif defined(TARGET_OS_WINDOWS)
    g_etw->SetEventCallback([](const TelemetryEvent& event) {
        if (g_sender) {
            g_sender->SendEvent(event);
        }
        // WS7: feed FileCreate events to the oplock-hold correlator.
        if (g_file_guard && event.header.event_type == EventType::FileCreate) {
            g_file_guard->NotifyFileCreate(event.details.file_create.file_path,
                                           event.header.pid);
        }
    });

    if (!g_etw->Start()) {
        std::cerr << "[FFI] Failed to start ETW Consumer" << std::endl;
        g_sender->Stop();
        return false;
    }

    if (g_file_guard) {
        g_file_guard->Start();
    }
    
    if (g_driver) {
        if (!g_driver->Start()) {
            std::cerr << "[FFI] Warning: Failed to start Driver Helper" << std::endl;
        }
    }

    if (g_clipboard) {
        g_clipboard->SetEventCallback([](const TelemetryEvent& event) {
            if (g_sender) {
                g_sender->SendEvent(event);
            }
        });
        if (!g_clipboard->Start()) {
            std::cerr << "[FFI] Warning: Failed to start Clipboard Helper" << std::endl;
        }
    }
#endif

    g_running = true;
    std::cout << "[FFI] Telemetry Engine started." << std::endl;
    return true;
}

void stop_telemetry_engine() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (!g_running) {
        return;
    }

#if defined(TARGET_OS_LINUX)
    g_tty_sender.Stop();
    if (g_loader) {
        g_loader->Stop();
    }
    if (g_fanotify) {
        g_fanotify->Stop();
    }
#elif defined(TARGET_OS_WINDOWS)
    // WS7: stop the guard worker first, while g_etw / the process registry it
    // reads through FileGuardEnforce are still alive. Stop() joins the worker,
    // so no break handler touches those globals afterwards.
    if (g_file_guard) {
        g_file_guard->Stop();
    }
    if (g_etw) {
        g_etw->Stop();
    }
    if (g_driver) {
        g_driver->Stop();
    }
    if (g_clipboard) {
        g_clipboard->Stop();
    }
#endif

    if (g_sender) {
        g_sender->Stop();
    }

    g_running = false;
    std::cout << "[FFI] Telemetry Engine stopped." << std::endl;
}

bool add_sensitive_inode(uint64_t dev, uint64_t inode, uint32_t category) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        bool ok = g_loader->AddSensitiveInode(dev, inode, category);
        // Phase 8 (LINUX_COVERAGE_PLAN.md): belt-and-suspenders -- also register
        // with the fanotify fallback so the resource stays protected even on a
        // kernel without BPF LSM support. Best-effort: the BPF-side result above
        // is authoritative, this doesn't affect the return value. No path
        // available at this call site (Rust passes dev+inode only), so this is
        // tracked in-memory only -- no live FAN_OPEN_PERM mark -- and is a
        // no-op either way while g_fanotify's Initialize() call keeps
        // enable_blocking at its default false (see that call site).
        if (g_fanotify) {
            g_fanotify->AddProtectedResource("", dev, inode);
        }
        return ok;
    }
#endif
    return false;
}

bool add_protected_static_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        bool ok = g_loader->AddProtectedStaticInode(dev, inode);
        if (g_fanotify) {
            g_fanotify->AddProtectedResource("", dev, inode);
        }
        return ok;
    }
#endif
    return false;
}

bool remove_protected_static_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        bool ok = g_loader->RemoveProtectedStaticInode(dev, inode);
        if (g_fanotify) {
            g_fanotify->RemoveProtectedResource("", dev, inode);
        }
        return ok;
    }
#endif
    return false;
}

bool add_bypassed_directory_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->AddBypassedDirectoryInode(dev, inode);
    }
#endif
    return false;
}

bool remove_bypassed_directory_inode(uint64_t dev, uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->RemoveBypassedDirectoryInode(dev, inode);
    }
#endif
    return false;
}


bool add_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->AddResourceOwner(resource_dev, resource_inode, owner_exec_inode);
    }
#endif
    return false;
}

bool remove_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->RemoveResourceOwner(resource_dev, resource_inode, owner_exec_inode);
    }
#endif
    return false;
}

bool add_trusted_exec_inode(uint64_t inode, uint32_t trust_level) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->AddTrustedExecInode(inode, trust_level);
    }
#endif
    return false;
}

// Fix 10: query whether an inode is registered in the trusted_exec_inodes BPF map.
// Used by the image_load() heuristic to detect SO side-loading into trusted processes.
bool is_trusted_exec_inode(uint64_t inode) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->LookupTrustedExecInode(inode);
    }
#endif
    return false;
}

bool set_config_value(uint32_t index, uint32_t value) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->SetConfigValue(index, value);
    }
#endif
    return false;
}

bool update_process_threshold(uint32_t pid, uint64_t start_time, uint32_t threshold) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->UpdateMapEntry(kinnector::lnx::BpfMapType::ProcessThreshold, pid, start_time, threshold);
    }
#endif
    return false;
}

bool update_map_entry(int map_type, uint32_t pid, uint64_t start_time, uint32_t value) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->UpdateMapEntry(static_cast<kinnector::lnx::BpfMapType>(map_type), pid, start_time, value);
    }
#endif
    return false;
}

bool delete_map_entry(int map_type, uint32_t pid, uint64_t start_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->DeleteMapEntry(static_cast<kinnector::lnx::BpfMapType>(map_type), pid, start_time);
    }
#endif
    return false;
}

bool is_lsm_active() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader) {
        return g_loader->IsLsmActive();
    }
#endif
    return false;
}

// Firewall (warden/src/firewall) — see ebpf_loader.h's AddFirewallCidr for
// the addr/prefixlen contract. `is_v6` selects fw_rules_v4 vs fw_rules_v6.
bool add_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                        uint32_t rule_id, uint16_t port, uint8_t proto,
                        uint8_t direction, uint8_t action) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->AddFirewallCidr(is_v6, addr, prefixlen, rule_id, port, proto, direction, action);
    }
#endif
    return false;
}

bool remove_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->RemoveFirewallCidr(is_v6, addr, prefixlen);
    }
#endif
    return false;
}

// Anti-tamper: -1 if unavailable (mock mode / not loaded), so the caller
// (warden/src/ebpf_health.rs) can distinguish "can't check" from "zero
// entries is correct."
int64_t count_firewall_entries() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->CountFirewallEntries();
    }
#endif
    return -1;
}

bool add_protected_resource_windows(uint32_t volume_serial, uint64_t file_reference_number, uint32_t category) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running) {
        return g_resource_store->AddProtectedResource(volume_serial, file_reference_number, category);
    }
#endif
    return false;
}

bool remove_protected_resource_windows(uint32_t volume_serial, uint64_t file_reference_number) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running) {
        return g_resource_store->RemoveProtectedResource(volume_serial, file_reference_number);
    }
#endif
    return false;
}

bool is_protected_resource_windows(uint32_t volume_serial, uint64_t file_reference_number, uint32_t* out_category) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running) {
        return g_resource_store->LookupProtectedResource(volume_serial, file_reference_number, out_category);
    }
#endif
    return false;
}

bool add_resource_owner_signer_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* signer_subject) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running && signer_subject) {
        return g_resource_store->AddResourceOwnerSigner(volume_serial, file_reference_number, signer_subject);
    }
#endif
    return false;
}

bool remove_resource_owner_signer_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* signer_subject) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running && signer_subject) {
        return g_resource_store->RemoveResourceOwnerSigner(volume_serial, file_reference_number, signer_subject);
    }
#endif
    return false;
}

bool is_authorized_signer_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* signer_subject) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running && signer_subject) {
        return g_resource_store->IsAuthorizedSigner(volume_serial, file_reference_number, signer_subject);
    }
#endif
    return false;
}

bool is_authorized_modifying_path_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* modifying_binary_path) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_running && modifying_binary_path) {
        return g_resource_store->IsAuthorizedModifyingPath(volume_serial, file_reference_number,
                                                             Utf8ToWstrFfi(modifying_binary_path));
    }
#endif
    return false;
}

bool add_protected_registry_key_windows(const char* key_path, uint32_t category, uint8_t subtree) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_registry_store && g_running && key_path) {
        return g_registry_store->AddProtectedKey(
            kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(key_path)),
            category, subtree != 0);
    }
#else
    (void)key_path; (void)category; (void)subtree;
#endif
    return false;
}

bool remove_protected_registry_key_windows(const char* key_path) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_registry_store && g_running && key_path) {
        return g_registry_store->RemoveProtectedKey(
            kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(key_path)));
    }
#else
    (void)key_path;
#endif
    return false;
}

bool is_protected_registry_key_windows(const char* key_path, uint32_t* out_category) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_registry_store && g_running && key_path) {
        return g_registry_store->LookupProtectedKey(
            kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(key_path)), out_category);
    }
#else
    (void)key_path; (void)out_category;
#endif
    return false;
}

bool add_registry_key_owner_signer_windows(const char* key_path, const char* signer_subject) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_registry_store && g_running && key_path && signer_subject) {
        return g_registry_store->AddOwnerSigner(
            kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(key_path)), signer_subject);
    }
#else
    (void)key_path; (void)signer_subject;
#endif
    return false;
}

bool remove_registry_key_owner_signer_windows(const char* key_path, const char* signer_subject) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_registry_store && g_running && key_path && signer_subject) {
        return g_registry_store->RemoveOwnerSigner(
            kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(key_path)), signer_subject);
    }
#else
    (void)key_path; (void)signer_subject;
#endif
    return false;
}

bool is_authorized_registry_signer_windows(const char* key_path, const char* signer_subject) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_registry_store && g_running && key_path && signer_subject) {
        return g_registry_store->IsAuthorizedSigner(
            kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(key_path)), signer_subject);
    }
#else
    (void)key_path; (void)signer_subject;
#endif
    return false;
}

bool resolve_actor_windows(uint32_t pid,
                            uint64_t* out_sequence_number,
                            uint64_t* out_create_time,
                            char* out_image_path, size_t out_image_path_len,
                            char* out_signer_subject, size_t out_signer_subject_len,
                            uint8_t* out_signed) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_etw && g_running) {
        kinnector::windows::ProcessRegistry::ActorInfo info;
        if (g_etw->GetProcessRegistry()->Lookup(pid, &info)) {
            if (out_sequence_number) *out_sequence_number = info.sequence_number;
            if (out_create_time)     *out_create_time = info.create_time;
            CopyOutStr(WstrToUtf8Ffi(info.image_path), out_image_path, out_image_path_len);
            CopyOutStr(info.signer_subject, out_signer_subject, out_signer_subject_len);
            if (out_signed) {
                *out_signed = info.signer_state ==
                                  kinnector::windows::ProcessRegistry::SignerState::Signed
                                  ? 1 : 0;
            }
            return true;
        }
    }
#else
    (void)pid; (void)out_sequence_number; (void)out_create_time;
    (void)out_image_path; (void)out_image_path_len;
    (void)out_signer_subject; (void)out_signer_subject_len; (void)out_signed;
#endif
    return false;
}

#if defined(TARGET_OS_WINDOWS)
// Shared by evaluate_access_windows: given a resolved actor, decide against a
// signer allowlist. Returns one of the WS4 verdict codes. Caller holds
// g_ffi_mutex. `check_signer` is the store's IsAuthorizedSigner bound to the
// specific protected resource.
} // extern "C"
namespace {
enum EvalVerdict { EV_NOT_PROTECTED = 0, EV_AUTHORIZED = 1, EV_UNAUTHORIZED = 2, EV_UNKNOWN_ACTOR = 3 };

uint32_t EvaluateActor(uint32_t actor_pid,
                       const std::function<bool(const std::string&)>& check_signer,
                       std::string* reason) {
    kinnector::windows::ProcessRegistry::ActorInfo ai;
    if (!g_etw->GetProcessRegistry()->Lookup(actor_pid, &ai)) {
        if (reason) *reason = "actor pid not tracked";
        return EV_UNKNOWN_ACTOR;
    }
    // Signer verification is async; if it hasn't landed yet, resolve it now
    // (this FFI is not on the ETW hot path).
    if (ai.signer_state == kinnector::windows::ProcessRegistry::SignerState::Pending &&
        !ai.image_path.empty()) {
        char buf[256] = {};
        bool ok = kinnector::windows::CachedVerifyAuthenticodeSignature(
            ai.image_path, buf, sizeof(buf));
        ai.signer_state = ok ? kinnector::windows::ProcessRegistry::SignerState::Signed
                             : kinnector::windows::ProcessRegistry::SignerState::Unsigned;
        ai.signer_subject = ok ? std::string(buf) : std::string();
    }
    if (ai.signer_state == kinnector::windows::ProcessRegistry::SignerState::Pending) {
        if (reason) *reason = "actor signer unresolved";
        return EV_UNKNOWN_ACTOR;
    }
    if (ai.signer_state == kinnector::windows::ProcessRegistry::SignerState::Signed &&
        check_signer(ai.signer_subject)) {
        if (reason) *reason = "actor signer in owner allowlist";
        return EV_AUTHORIZED;
    }
    if (reason) {
        *reason = ai.signer_state == kinnector::windows::ProcessRegistry::SignerState::Signed
                      ? "actor signer not in owner allowlist"
                      : "actor is unsigned";
    }
    return EV_UNAUTHORIZED;
}

// WS7: verdict + response for a correlated oplock break. Runs on the FileGuard
// worker thread, NOT under g_ffi_mutex - taking it here would deadlock against
// stop_telemetry_engine (which holds g_ffi_mutex while FileGuard::Stop() joins
// this thread). Safe without it: FileGuard::Stop() runs before any of these
// globals are reset, and they are never reassigned after init.
//
// The opener's identity is resolved SYNCHRONOUSLY here (OpenProcess +
// QueryFullProcessImageNameW + GetProcessTimes + a cached Authenticode
// check), NOT via the ProcessRegistry - under heavy ETW load that registry
// lags seconds behind and a just-spawned stealer would not be in it. The
// owner-set decision is identical to EvaluateActor's: signed AND signer in
// the resource's owner set -> authorized; anything else -> UNAUTHORIZED.
//
// `candidate_pids` is every process that fired a create for the guarded file
// around the break (the real opener plus, often, an AV real-time scan). We
// evaluate each and act on the first actionable one - a protected/system
// process (AV) simply fails the OpenProcess/query and is skipped. The per-pid
// lines it logs are the audit trail of what touched a flagship credential file.

// One candidate. -1 = keep looking, 0 = definitively authorized (stop), 1 = suspended.
static int FileGuardEvalOne(uint32_t pid, uint32_t volume_serial, uint64_t frn) {
    HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!q) return -1;  // protected/exited - not the actionable opener
    wchar_t img[1024] = {};
    DWORD img_len = 1024;
    bool got_img = QueryFullProcessImageNameW(q, 0, img, &img_len) != 0;
    FILETIME cr{}, ex{}, kt{}, ut{};
    bool got_ct = GetProcessTimes(q, &cr, &ex, &kt, &ut) != 0;
    CloseHandle(q);
    if (!got_img || !got_ct || img_len == 0 || img_len >= 1024) return -1;

    const uint64_t create_time =
        (static_cast<uint64_t>(cr.dwHighDateTime) << 32) | cr.dwLowDateTime;
    std::wstring image_path(img, img_len);

    char signer[256] = {};
    bool signed_ok = kinnector::windows::CachedVerifyAuthenticodeSignature(
        image_path, signer, sizeof(signer));
    std::cout << "[file_guard] pid " << pid << " image='" << WstrToUtf8Ffi(image_path)
              << "' signed=" << signed_ok << " signer='" << signer << "'\n";

    if (signed_ok &&
        g_resource_store->IsAuthorizedSigner(volume_serial, frn, std::string(signer))) {
        std::cout << "[file_guard] pid " << pid << " authorized (signer in owner set)\n";
        return 0;
    }

    const char* why = signed_ok ? "signer not in owner set" : "unsigned/untrusted";
    if (!g_response->EnforcementEnabled()) {
        std::cout << "[file_guard] pid " << pid << " UNAUTHORIZED (" << why
                  << ") but response disarmed - fail open\n";
        return -1;
    }
    bool ok = g_etw && g_response->Suspend(pid, 0, create_time,
                                           g_etw->GetProcessRegistry());
    std::cout << "[file_guard] pid " << pid << " UNAUTHORIZED (" << why
              << ") - suspend " << (ok ? "OK" : "FAILED") << "\n";
    return ok ? 1 : -1;
}

kinnector::windows::FileGuard::EnforceResult FileGuardEnforce(
    const std::vector<uint32_t>& candidate_pids, uint32_t volume_serial, uint64_t frn) {
    using R = kinnector::windows::FileGuard::EnforceResult;
    using V = kinnector::windows::FileGuard::Verdict;
    if (!g_resource_store || !g_response) return R{};
    if (!g_resource_store->LookupProtectedResource(volume_serial, frn, nullptr)) {
        std::cout << "[file_guard] vol=" << volume_serial << " frn=" << frn
                  << " not a registered protected resource - fail open\n";
        return R{};
    }
    for (uint32_t pid : candidate_pids) {
        int r = FileGuardEvalOne(pid, volume_serial, frn);
        if (r == 1) return R{V::Suspended, pid};
        if (r == 0) return R{V::Authorized, pid};
    }
    return R{};
}
} // namespace
extern "C" {
#endif

bool evaluate_access_windows(uint32_t actor_pid, uint32_t target_kind,
                              const char* target_id, uint32_t* out_verdict,
                              char* out_reason, size_t out_reason_len) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (!g_running || !target_id || !g_etw) return false;
    std::string reason;
    uint32_t verdict = EV_NOT_PROTECTED;

    if (target_kind == 1) {  // file path
        auto id = kinnector::windows::ResolveCanonicalResourceIdentity(Utf8ToWstrFfi(target_id));
        if (!id.valid) {
            reason = "path did not resolve";
        } else if (!g_resource_store ||
                   !g_resource_store->LookupProtectedResource(id.volume_serial,
                                                              id.file_reference_number, nullptr)) {
            reason = "resource not protected";
        } else {
            verdict = EvaluateActor(actor_pid, [&](const std::string& s) {
                return g_resource_store->IsAuthorizedSigner(id.volume_serial,
                                                            id.file_reference_number, s);
            }, &reason);
        }
    } else if (target_kind == 2) {  // registry key
        std::wstring canon = kinnector::windows::CanonicalizeRegistryKey(Utf8ToWstrFfi(target_id));
        if (!g_registry_store || !g_registry_store->LookupProtectedKey(canon, nullptr)) {
            reason = "key not protected";
        } else {
            verdict = EvaluateActor(actor_pid, [&](const std::string& s) {
                return g_registry_store->IsAuthorizedSigner(canon, s);
            }, &reason);
        }
    } else {
        reason = "unknown target_kind";
    }

    if (out_verdict) *out_verdict = verdict;
    CopyOutStr(reason, out_reason, out_reason_len);
    return true;
#else
    (void)actor_pid; (void)target_kind; (void)target_id;
    (void)out_verdict; (void)out_reason; (void)out_reason_len;
    return false;
#endif
}

bool set_response_enforcement_windows(uint8_t enabled) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_response) {
        g_response->SetEnforcementEnabled(enabled != 0);
        return true;
    }
#else
    (void)enabled;
#endif
    return false;
}

bool suspend_process_windows(uint32_t pid, uint64_t expected_sequence_number,
                              uint64_t expected_create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_response && g_etw && g_running) {
        return g_response->Suspend(pid, expected_sequence_number, expected_create_time,
                                   g_etw->GetProcessRegistry());
    }
#else
    (void)pid; (void)expected_sequence_number; (void)expected_create_time;
#endif
    return false;
}

bool resume_process_windows(uint32_t pid, uint64_t expected_sequence_number,
                             uint64_t expected_create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_response && g_etw && g_running) {
        return g_response->Resume(pid, expected_sequence_number, expected_create_time,
                                  g_etw->GetProcessRegistry());
    }
#else
    (void)pid; (void)expected_sequence_number; (void)expected_create_time;
#endif
    return false;
}

bool terminate_process_windows(uint32_t pid, uint64_t expected_sequence_number,
                                uint64_t expected_create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_response && g_etw && g_running) {
        return g_response->Terminate(pid, expected_sequence_number, expected_create_time,
                                     g_etw->GetProcessRegistry());
    }
#else
    (void)pid; (void)expected_sequence_number; (void)expected_create_time;
#endif
    return false;
}

bool set_telemetry_profile_windows(uint32_t profile) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_etw && g_initialized && !g_running) {
        g_etw->SetProfile(profile == 1
                              ? kinnector::windows::EtwConsumer::Profile::Reactive
                              : kinnector::windows::EtwConsumer::Profile::Full);
        return true;
    }
#else
    (void)profile;
#endif
    return false;
}

bool telemetry_abi_windows(uint32_t* out_event_size, uint32_t* out_header_size) {
#if defined(TARGET_OS_WINDOWS)
    if (out_event_size)  *out_event_size  = static_cast<uint32_t>(sizeof(TelemetryEvent));
    if (out_header_size) *out_header_size = static_cast<uint32_t>(sizeof(TelemetryHeader));
    return true;
#else
    (void)out_event_size; (void)out_header_size;
    return false;
#endif
}

bool add_telemetry_path_filter_windows(const char* path) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_etw && path && path[0]) {
        g_etw->AddEmitPathFilter(Utf8ToWstrFfi(path));
        return true;
    }
#else
    (void)path;
#endif
    return false;
}

bool clear_telemetry_path_filter_windows(void) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_etw) {
        g_etw->ClearEmitPathFilters();
        return true;
    }
#endif
    return false;
}

bool get_telemetry_stats_windows(uint64_t* out_events_processed,
                                 uint64_t* out_events_lost,
                                 uint64_t* out_buffers_written,
                                 double* out_p50_ms, double* out_p95_ms,
                                 double* out_p99_ms, double* out_max_ms) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_etw && g_running) {
        auto s = g_etw->GetStats();
        if (out_events_processed) *out_events_processed = s.events_processed;
        if (out_events_lost)      *out_events_lost = s.events_lost;
        if (out_buffers_written)  *out_buffers_written = s.buffers_written;
        if (out_p50_ms) *out_p50_ms = s.p50_ms;
        if (out_p95_ms) *out_p95_ms = s.p95_ms;
        if (out_p99_ms) *out_p99_ms = s.p99_ms;
        if (out_max_ms) *out_max_ms = s.max_ms;
        return true;
    }
#else
    (void)out_events_processed; (void)out_events_lost; (void)out_buffers_written;
    (void)out_p50_ms; (void)out_p95_ms; (void)out_p99_ms; (void)out_max_ms;
#endif
    return false;
}

bool add_file_guard_windows(const char* path) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_file_guard && g_running && path && path[0]) {
        std::wstring wpath = Utf8ToWstrFfi(path);
        auto id = kinnector::windows::ResolveCanonicalResourceIdentity(wpath);
        if (!id.valid || !g_resource_store ||
            !g_resource_store->LookupProtectedResource(id.volume_serial,
                                                       id.file_reference_number, nullptr)) {
            std::cerr << "[file_guard] '" << path << "' is not a registered protected "
                         "resource yet - guard armed but inert until it is\n";
        }
        return g_file_guard->AddGuard(wpath);
    }
#else
    (void)path;
#endif
    return false;
}

bool remove_file_guard_windows(const char* path) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_file_guard && g_running && path && path[0]) {
        return g_file_guard->RemoveGuard(Utf8ToWstrFfi(path));
    }
#else
    (void)path;
#endif
    return false;
}

bool flag_process_injected_windows(uint32_t pid, uint64_t create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_process_integrity && g_running) {
        return g_process_integrity->FlagProcessInjected(pid, create_time);
    }
#endif
    return false;
}

bool clear_process_flag_windows(uint32_t pid, uint64_t create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_process_integrity && g_running) {
        return g_process_integrity->ClearProcessFlag(pid, create_time);
    }
#endif
    return false;
}

bool is_process_clear_windows(uint32_t pid, uint64_t create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_process_integrity && g_running) {
        return g_process_integrity->IsProcessClear(pid, create_time);
    }
#endif
    return false;
}

bool is_authorized_self_update_windows(uint32_t volume_serial, uint64_t file_reference_number,
                                        const char* modifying_binary_path,
                                        uint32_t modifying_pid, uint64_t modifying_process_create_time) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_WINDOWS)
    if (g_resource_store && g_process_integrity && g_running && modifying_binary_path) {
        return kinnector::windows::IsAuthorizedSelfUpdate(
            *g_resource_store, *g_process_integrity, volume_serial, file_reference_number,
            Utf8ToWstrFfi(modifying_binary_path), modifying_pid, modifying_process_create_time);
    }
#endif
    return false;
}

bool send_telemetry_event(const TelemetryEvent* event) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
    if (g_sender && g_running && event) {
        return g_sender->SendEvent(*event);
    }
    return false;
}

} // extern "C"
