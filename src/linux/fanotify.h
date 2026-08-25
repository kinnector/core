#ifndef KINNECTOR_FANOTIFY_H
#define KINNECTOR_FANOTIFY_H

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <mutex>
#include <unordered_set>
#include <cstdint>
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

    // Phase 8 (LINUX_COVERAGE_PLAN.md): belt-and-suspenders blocking for kernels
    // without BPF LSM support, mirroring EbpfLoader's LSM/fallback-tracepoint
    // split. Unlike the LSM path, fallback mode has no per-process trust state
    // available cheaply, so the policy here is intentionally crude: any
    // registered resource is denied to *every* process, full stop -- coarser
    // than the LSM owner-allowlist, but real synchronous denial where
    // previously there was none at all. `dev`/`ino` mirror kinnector.bpf.c's
    // (dev, ino) resource_id identity (Phase 6) so callers can reuse the same
    // stat() result they already resolve for the BPF-side registration.
    bool AddProtectedResource(uint64_t dev, uint64_t ino);
    bool RemoveProtectedResource(uint64_t dev, uint64_t ino);

    // Checks if the active fanotify group supports permission events (i.e.
    // Initialize() succeeded with FAN_CLASS_CONTENT, not just notification).
    bool IsPermissionCapable() const { return permission_capable_; }

private:
    void MonitorLoop();
    bool IsProtectedResource(uint64_t dev, uint64_t ino);

    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> permission_capable_{false};
    int fanotify_fd_{-1};
    std::string mount_path_;
    std::thread monitor_thread_;
    EventCallback event_callback_;

    struct ResourceId {
        uint64_t dev;
        uint64_t ino;
        bool operator==(const ResourceId& o) const { return dev == o.dev && ino == o.ino; }
    };
    struct ResourceIdHash {
        size_t operator()(const ResourceId& r) const {
            return std::hash<uint64_t>()(r.dev) ^ (std::hash<uint64_t>()(r.ino) << 1);
        }
    };
    std::mutex protected_resources_mutex_;
    std::unordered_set<ResourceId, ResourceIdHash> protected_resources_;
};

} // namespace kinnector::lnx

#endif // KINNECTOR_FANOTIFY_H
