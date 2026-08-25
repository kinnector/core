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

    // Phase 8 (LINUX_COVERAGE_PLAN.md), post-incident revision: `enable_blocking`
    // defaults to false and MUST stay that way for any general-purpose caller
    // (initialize_telemetry_engine included). Passing true attempts
    // FAN_CLASS_CONTENT + FAN_MARK_MOUNT FAN_OPEN_PERM on `mount_path` -- this
    // makes EVERY open() by EVERY process on that mount block on this object's
    // single monitor thread until it responds. Marking "/" this way took down
    // the entire dev machine the first time it ever actually ran (previously
    // masked in every test because fanotify_init(FAN_CLASS_CONTENT) silently
    // failed without CAP_SYS_ADMIN, i.e. under any non-root run). Only pass
    // true against a mount_path you are certain is narrow and disposable (a
    // dedicated tmpfs/test directory), never a real system mount, until the
    // per-path-mark follow-up below exists.
    //
    // KNOWN LIMITATION, not yet fixed: this should mark individual protected
    // paths (FAN_MARK_ADD per file) instead of the whole mount, so blast
    // radius is limited to actually-registered resources -- needs the
    // resource's path threaded through the FFI boundary from Rust, which
    // neither warden nor antitheft-agent currently pass (only dev+inode).
    // Do not flip any caller to enable_blocking=true against a real mount
    // until that's built.
    bool Initialize(const std::string& mount_path = "/", bool enable_blocking = false);
    bool Start();
    void Stop();

    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

    // Only meaningful when Initialize() was called with enable_blocking=true.
    // `dev`/`ino` mirror kinnector.bpf.c's (dev, ino) resource_id identity
    // (Phase 6) so callers can reuse the same stat() result they already
    // resolve for the BPF-side registration. `path` establishes a real
    // per-path FAN_OPEN_PERM mark (FAN_MARK_ADD, deliberately never
    // FAN_MARK_MOUNT) -- pass the empty string to track the resource
    // in-memory only, without a live kernel-side mark (e.g. when the caller
    // doesn't have a path, only dev+inode); this is a safe degrade, not a
    // silent no-op, and logs when it happens. Policy is intentionally crude:
    // any marked resource is denied to *every* process, full stop -- fallback
    // mode has no per-process trust state available cheaply the way the LSM
    // path does.
    bool AddProtectedResource(const std::string& path, uint64_t dev, uint64_t ino);
    bool RemoveProtectedResource(const std::string& path, uint64_t dev, uint64_t ino);

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
