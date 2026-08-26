#pragma once
// windows.h pulls in the legacy winsock.h unless this is set, which then
// conflicts with winsock2.h/ws2tcpip.h included later (by etw_consumer.cpp)
// - macro redefinitions followed by hard parse errors in ws2tcpip.h.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "kinnector/telemetry.h"
#include <functional>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

namespace kinnector::windows {

class EtwConsumer {
public:
    EtwConsumer();
    ~EtwConsumer();

    bool Initialize();
    bool Start();
    void Stop();
    
    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

    // Public: assigned as an OS callback (EVENT_TRACE_LOGFILEW::EventRecordCallback)
    // from the free-standing trace thread in etw_consumer.cpp, not just from members.
    static void WINAPI EventRecordCallback(PEVENT_RECORD event);

private:
    void ProcessEvent(PEVENT_RECORD event);

    EventCallback callback_;
    TRACEHANDLE session_handle_;
    TRACEHANDLE trace_handle_;
    HANDLE thread_handle_;
    bool running_;
    
    static EtwConsumer* instance_;
};

}
