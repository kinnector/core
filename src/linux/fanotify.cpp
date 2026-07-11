#include "fanotify.h"
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <cstring>
#include <iostream>
#include <chrono>

namespace kinnector::lnx {

FanotifyMonitor::FanotifyMonitor() = default;

FanotifyMonitor::~FanotifyMonitor() {
    Stop();
}

bool FanotifyMonitor::Initialize(const std::string& mount_path) {
    if (initialized_) {
        return false;
    }

    mount_path_ = mount_path;

    // Initialize fanotify notification group
    fanotify_fd_ = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);
    if (fanotify_fd_ < 0) {
        std::cerr << "[Fanotify] Failed to initialize fanotify: " << std::strerror(errno) << std::endl;
        return false;
    }

    // Mark the mount point to monitor file modification and write completion
    int ret = fanotify_mark(
        fanotify_fd_,
        FAN_MARK_ADD | FAN_MARK_MOUNT,
        FAN_MODIFY | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD,
        AT_FDCWD,
        mount_path_.c_str()
    );

    if (ret < 0) {
        std::cerr << "[Fanotify] Failed to add fanotify mark on " << mount_path_ 
                  << ": " << std::strerror(errno) << std::endl;
        close(fanotify_fd_);
        fanotify_fd_ = -1;
        return false;
    }

    initialized_ = true;
    std::cout << "[Fanotify] File Integrity Monitor initialized on mount: " << mount_path_ << std::endl;
    return true;
}

bool FanotifyMonitor::Start() {
    if (!initialized_ || running_) {
        return false;
    }

    running_ = true;
    monitor_thread_ = std::thread(&FanotifyMonitor::MonitorLoop, this);
    std::cout << "[Fanotify] File Integrity Monitor thread started." << std::endl;
    return true;
}

void FanotifyMonitor::Stop() {
    if (!running_) {
        return;
    }

    running_ = false;

    if (fanotify_fd_ != -1) {
        // Closing the fd will unblock any blocking read() in the monitor loop
        close(fanotify_fd_);
        fanotify_fd_ = -1;
    }

    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }

    initialized_ = false;
    std::cout << "[Fanotify] File Integrity Monitor stopped." << std::endl;
}

void FanotifyMonitor::SetEventCallback(EventCallback cb) {
    event_callback_ = cb;
}

void FanotifyMonitor::MonitorLoop() {
    alignas(struct fanotify_event_metadata) char buf[8192];
    static uint64_t seq = 0;

    while (running_) {
        ssize_t len = read(fanotify_fd_, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            // If the socket was closed, break the loop
            if (errno == EBADF || !running_) {
                break;
            }
            std::cerr << "[Fanotify] Error reading fanotify event: " << std::strerror(errno) << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        auto* metadata = reinterpret_cast<struct fanotify_event_metadata*>(buf);
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->metadata_len < FAN_EVENT_METADATA_LEN) {
                break;
            }

            if (metadata->fd >= 0) {
                // Resolve path using /proc/self/fd/
                char path[PATH_MAX];
                char proc_path[64];
                std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", metadata->fd);
                ssize_t path_len = readlink(proc_path, path, sizeof(path) - 1);
                
                if (path_len > 0) {
                    path[path_len] = '\0';
                    
                    std::string path_str(path);

                    // Filter out noisy paths to prevent feedback loops and system noise
                    bool should_filter = path_str.empty() ||
                                         path_str.find("/proc/") == 0 ||
                                         path_str.find("/sys/") == 0 ||
                                         path_str.find("/dev/") == 0 ||
                                         path_str.find("/run/") != std::string::npos ||
                                         path_str.find("/var/run/") != std::string::npos ||
                                         path_str.find("/var/log/") != std::string::npos ||
                                         path_str.find("/tmp/") == 0 ||
                                         path_str.find(".gemini") != std::string::npos ||
                                         path_str.find("kinnector.bpf.o") != std::string::npos;

                    if (!should_filter && event_callback_) {
                        TelemetryEvent event{};
                        event.header.sequence_number = ++seq;
                        event.header.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()
                        ).count();
                        event.header.pid = metadata->pid;
                        event.header.event_type = EventType::FileWrite;
                        event.header.source = TelemetrySource::fanotify;

                        std::strncpy(event.details.file_write.file_path, path, sizeof(event.details.file_write.file_path) - 1);
                        event.details.file_write.bytes_written = 0; // Close write event

                        event_callback_(event);
                    }
                }

                close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

} // namespace kinnector::lnx
