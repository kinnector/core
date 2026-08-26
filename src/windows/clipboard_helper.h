#pragma once
#include "kinnector/telemetry.h"
#include <functional>
#include <windows.h>
#include <atomic>
#include <string>
#include <thread>

namespace kinnector::windows {

class ClipboardHelper {
public:
    ClipboardHelper();
    ~ClipboardHelper();

    bool Initialize();
    bool Start();
    void Stop();

    using EventCallback = std::function<void(const TelemetryEvent&)>;
    void SetEventCallback(EventCallback cb);

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    void MessageLoop();
    void OnClipboardUpdate();

    EventCallback callback_;
    HWND hwnd_;
    std::thread thread_;
    std::atomic<bool> running_;
    std::string last_content_;
    uint64_t sequence_;

    static ClipboardHelper* instance_;
};

}
