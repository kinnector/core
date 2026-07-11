#pragma once
#include "kinnector/ipc.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <mutex>

namespace kinnector::ipc::windows {
class WindowsTelemetrySender : public ITelemetrySender {
public:
    WindowsTelemetrySender();
    ~WindowsTelemetrySender() override;

    bool Start(const IPCConfig& config) override;
    void Stop() override;
    bool SendEvent(const TelemetryEvent& event) override;
    bool IsConnected() const override;

private:
    void ConnectionLoop();
    
    std::string pipe_name_;
    std::string auth_token_;
    HANDLE pipe_handle_;
    std::atomic<bool> running_;
    std::atomic<bool> connected_;
    std::thread connection_thread_;
    std::mutex send_mutex_;
};
}
