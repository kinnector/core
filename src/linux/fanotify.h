#ifndef KINNECTOR_FANOTIFY_H
#define KINNECTOR_FANOTIFY_H

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include "kinnector/telemetry.h"

namespace kinnector::lnx {

class FanotifyMonitor {
public:
    FanotifyMonitor();
    ~FanotifyMonitor();

    bool Initialize(const std::string& mount_path = "/");
    bool Start();
    void Stop();

    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

private:
    void MonitorLoop();

    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    int fanotify_fd_{-1};
    std::string mount_path_;
    std::thread monitor_thread_;
    EventCallback event_callback_;
};

} // namespace kinnector::lnx

#endif // KINNECTOR_FANOTIFY_H
