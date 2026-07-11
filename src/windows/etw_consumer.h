#pragma once
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

private:
    static void WINAPI EventRecordCallback(PEVENT_RECORD event);
    void ProcessEvent(PEVENT_RECORD event);

    EventCallback callback_;
    TRACEHANDLE session_handle_;
    TRACEHANDLE trace_handle_;
    HANDLE thread_handle_;
    bool running_;
    
    static EtwConsumer* instance_;
};

}
