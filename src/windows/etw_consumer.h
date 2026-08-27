#pragma once
// windows.h pulls in the legacy winsock.h unless this is set, which then
// conflicts with winsock2.h/ws2tcpip.h included later (by etw_consumer.cpp)
// - macro redefinitions followed by hard parse errors in ws2tcpip.h.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "kinnector/telemetry.h"
#include "process_registry.h"
#include <functional>
#include <mutex>
#include <string>
#include <unordered_set>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

namespace kinnector::windows {

class EtwConsumer {
public:
    // Full        - every provider/keyword as historically enabled (file
    //               read+write, ImageLoad, thread, UDP send, ...). What the
    //               Phase 1-3 collector tests expect.
    // Reactive    - the minimal set the driver-less reactive MVP needs:
    //               process create/stop, file create/delete/rename (no
    //               read/write - flagship reads are covered by the WS7 oplock),
    //               registry mutations, TCP connect/accept, TaskScheduler,
    //               DPAPI. Drops the highest-volume event types so the single
    //               ProcessTrace callback thread keeps up under load. See
    //               MVP_REACTIVE_PLAN.md "WS6 event-volume reduction".
    enum class Profile { Full, Reactive };

    EtwConsumer();
    ~EtwConsumer();

    bool Initialize();
    // Must be called before Start(); no-op once running.
    void SetProfile(Profile p) { profile_ = p; }
    bool Start();
    void Stop();

    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

    // Emit-path filter: when non-empty, file Create/Delete/Rename events are
    // forwarded to the callback ONLY if the file's basename (case-insensitive)
    // is registered here. A CREATE storm from a process launch (DLL opens etc.)
    // then costs just schema-lookup + one property read + a hashset check, not
    // a full parse + struct build + IPC send. Empty => forward everything
    // (default; the Full-profile collector tests rely on it). Process/network/
    // task/DPAPI events are never filtered by this. The agent must keep this in
    // sync with the paths behind its protected-resource registrations.
    void AddEmitPathFilter(const std::wstring& path);
    void ClearEmitPathFilters();

    struct Stats {
        uint64_t events_processed = 0;
        uint64_t events_lost = 0;
        uint64_t buffers_written = 0;
        double p50_ms = 0, p95_ms = 0, p99_ms = 0, max_ms = 0;
        uint64_t schema_hits = 0, schema_misses = 0, schema_canary_mismatch = 0;
    };
    Stats GetStats() const;

    // WS1: the live pid -> reuse-safe identity map, fed from this consumer's
    // Kernel-Process handling. Shared with the resolve_actor_windows /
    // evaluate_access_windows / *_process_windows FFI. Never null after
    // construction.
    ProcessRegistry* GetProcessRegistry() { return &process_registry_; }

    // Public: assigned as an OS callback (EVENT_TRACE_LOGFILEW::EventRecordCallback)
    // from the free-standing trace thread in etw_consumer.cpp, not just from members.
    static void WINAPI EventRecordCallback(PEVENT_RECORD event);

private:
    void ProcessEvent(PEVENT_RECORD event);
    // Enable the ETW providers on session_handle_ according to profile_.
    // Split out of Initialize() so SetProfile() can run between the two.
    bool EnableProviders();

    // true if `file_path` (an ETW \Device path, UTF-8) should be forwarded
    // given the current emit-path filter.
    bool ShouldEmitFilePath(const std::string& file_path) const;

    EventCallback callback_;
    ProcessRegistry process_registry_;
    Profile profile_ = Profile::Full;
    mutable std::mutex emit_filter_mutex_;
    std::unordered_set<std::wstring> emit_basenames_;  // upper-cased
    TRACEHANDLE session_handle_;
    TRACEHANDLE trace_handle_;
    HANDLE thread_handle_;
    bool running_;

    static EtwConsumer* instance_;
};

}
