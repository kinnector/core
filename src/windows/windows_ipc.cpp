#include "windows_ipc.h"
#include <iostream>
#include <vector>

namespace kinnector::ipc::windows {

WindowsTelemetrySender::WindowsTelemetrySender() 
    : pipe_handle_(INVALID_HANDLE_VALUE), running_(false), connected_(false) {}

WindowsTelemetrySender::~WindowsTelemetrySender() {
    Stop();
}

bool WindowsTelemetrySender::Start(const IPCConfig& config) {
    if (running_) return false;
    
    if (!config.pipe_name.empty()) {
        pipe_name_ = config.pipe_name;
    } else {
        pipe_name_ = "\\\\.\\pipe\\kinnector-ipc";
    }
    
    auth_token_ = config.auth_token;
    running_ = true;
    connection_thread_ = std::thread(&WindowsTelemetrySender::ConnectionLoop, this);
    return true;
}

void WindowsTelemetrySender::Stop() {
    running_ = false;
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_handle_);
        pipe_handle_ = INVALID_HANDLE_VALUE;
    }
    connected_ = false;
    if (connection_thread_.joinable()) {
        connection_thread_.join();
    }
}

bool WindowsTelemetrySender::SendEvent(const TelemetryEvent& event) {
    if (!connected_) return false;
    std::lock_guard<std::mutex> lock(send_mutex_);
    if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL result = WriteFile(pipe_handle_, &event, sizeof(TelemetryEvent), &written, NULL);
    if (!result || written != sizeof(TelemetryEvent)) {
        CloseHandle(pipe_handle_);
        pipe_handle_ = INVALID_HANDLE_VALUE;
        connected_ = false;
        return false;
    }
    return true;
}

bool WindowsTelemetrySender::IsConnected() const {
    return connected_;
}

void WindowsTelemetrySender::ConnectionLoop() {
    while (running_) {
        if (connected_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        HANDLE hPipe = CreateFileA(
            pipe_name_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            uint32_t len = (uint32_t)auth_token_.length();
            DWORD written = 0;
            WriteFile(hPipe, &len, sizeof(len), &written, NULL);
            WriteFile(hPipe, auth_token_.c_str(), len, &written, NULL);

            uint8_t status = 0;
            DWORD read_bytes = 0;
            if (ReadFile(hPipe, &status, sizeof(status), &read_bytes, NULL) && status == 1) {
                std::lock_guard<std::mutex> lock(send_mutex_);
                pipe_handle_ = hPipe;
                connected_ = true;
            } else {
                CloseHandle(hPipe);
            }
        }

        if (!connected_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

}
