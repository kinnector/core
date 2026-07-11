#include "kinnector/ffi.h"
#include "kinnector/ipc.h"

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
#include <windows.h>
static std::unique_ptr<kinnector::windows::EtwConsumer> g_etw = nullptr;
static std::unique_ptr<kinnector::windows::DriverHelper> g_driver = nullptr;
static HANDLE g_clipboard_process = NULL;
#endif

static std::mutex g_ffi_mutex;
static bool g_initialized = false;
static bool g_running = false;

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
    });
    
    if (!g_etw->Start()) {
        std::cerr << "[FFI] Failed to start ETW Consumer" << std::endl;
        g_sender->Stop();
        return false;
    }
    
    if (g_driver) {
        if (!g_driver->Start()) {
            std::cerr << "[FFI] Warning: Failed to start Driver Helper" << std::endl;
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
    if (g_etw) {
        g_etw->Stop();
    }
    if (g_driver) {
        g_driver->Stop();
    }
#endif

    if (g_sender) {
        g_sender->Stop();
    }

    g_running = false;
    std::cout << "[FFI] Telemetry Engine stopped." << std::endl;
}

bool add_sensitive_inode(uint64_t inode, uint32_t category) {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader && g_running) {
        return g_loader->AddSensitiveInode(inode, category);
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

bool is_lsm_active() {
    std::lock_guard<std::mutex> lock(g_ffi_mutex);
#if defined(TARGET_OS_LINUX)
    if (g_loader) {
        return g_loader->IsLsmActive();
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
