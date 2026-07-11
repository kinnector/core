#include "linux_ipc.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

namespace kinnector::ipc::lnx {

LinuxTelemetrySender::LinuxTelemetrySender() = default;

LinuxTelemetrySender::~LinuxTelemetrySender() {
    Stop();
}

bool LinuxTelemetrySender::Start(const IPCConfig& config) {
    if (running_) {
        return false;
    }
    config_ = config;
    running_ = true;
    connection_thread_ = std::thread(&LinuxTelemetrySender::ConnectionLoop, this);
    return true;
}

void LinuxTelemetrySender::Stop() {
    running_ = false;
    connected_ = false;
    
    int fd = socket_fd_.exchange(-1);
    if (fd != -1) {
        close(fd);
    }
    
    if (connection_thread_.joinable()) {
        connection_thread_.join();
    }
}

bool LinuxTelemetrySender::SendEvent(const TelemetryEvent& event) {
    if (!connected_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(send_mutex_);
    int fd = socket_fd_.load();
    if (fd == -1) {
        return false;
    }
    
    // Write event structure to socket
    ssize_t written = write(fd, &event, sizeof(TelemetryEvent));
    if (written != sizeof(TelemetryEvent)) {
        std::cerr << "Failed to send complete telemetry event" << std::endl;
        connected_ = false;
        close(fd);
        socket_fd_ = -1;
        return false;
    }
    return true;
}

bool LinuxTelemetrySender::IsConnected() const {
    return connected_;
}

void LinuxTelemetrySender::ConnectionLoop() {
    while (running_) {
        if (connected_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        
        struct sockaddr_un addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, config_.socket_path.c_str(), sizeof(addr.sun_path) - 1);
        
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        
        // Enforce socket permissions/security (verify permissions are not too open on disk)
        struct stat st;
        if (stat(config_.socket_path.c_str(), &st) == 0) {
            if (st.st_mode & (S_IWOTH | S_IXOTH | S_IWGRP | S_IXGRP)) {
                std::cerr << "IPC Socket has insecure permissions: " << std::oct << (st.st_mode & 0777) << std::dec << std::endl;
                close(fd);
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }
        
        if (PerformHandshake(fd)) {
            socket_fd_ = fd;
            connected_ = true;
        } else {
            std::cerr << "IPC Handshake failed" << std::endl;
            close(fd);
        }
    }
}

bool LinuxTelemetrySender::PerformHandshake(int fd) {
    if (config_.auth_token.empty()) {
        return true;
    }
    
    // We send the length of the token, followed by the token string
    uint32_t len = static_cast<uint32_t>(config_.auth_token.size());
    if (write(fd, &len, sizeof(len)) != sizeof(len)) {
        return false;
    }
    if (write(fd, config_.auth_token.data(), len) != static_cast<ssize_t>(len)) {
        return false;
    }
    
    // Wait for auth confirmation from agent (1 byte status code: 1 = success, 0 = fail)
    uint8_t status = 0;
    if (read(fd, &status, sizeof(status)) != sizeof(status)) {
        return false;
    }
    
    return status == 1;
}

} // namespace kinnector::ipc::lnx
