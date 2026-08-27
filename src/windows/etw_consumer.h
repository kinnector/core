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

    EventCallback callback_;
    ProcessRegistry process_registry_;
    Profile profile_ = Profile::Full;
    TRACEHANDLE session_handle_;
    TRACEHANDLE trace_handle_;
    HANDLE thread_handle_;
    bool running_;

    static EtwConsumer* instance_;
};

}
