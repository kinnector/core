#ifndef KINNECTOR_IPC_H
#define KINNECTOR_IPC_H

#include <string>
#include <vector>
#include <memory>
#include "telemetry.h"

namespace kinnector::ipc {

// Configuration for IPC setup
struct IPCConfig {
    std::string socket_path;       // Unix domain socket path (Linux/macOS)
    std::string pipe_name;         // Named pipe name (Windows)
    std::string auth_token;        // Cryptographic token for handshake authentication
    bool is_fallback_tcp = false;  // Fallback to TCP loopback
    int tcp_port = 4080;
};

// Interface for telemetry dispatcher
class ITelemetrySender {
public:
    virtual ~ITelemetrySender() = default;
    
    // Starts the IPC sender and waits for connection/handshake
    virtual bool Start(const IPCConfig& config) = 0;
    
    // Stops the IPC sender
    virtual void Stop() = 0;
    
    // Sends a telemetry event synchronously or queues it
    virtual bool SendEvent(const TelemetryEvent& event) = 0;
    
    // Checks if the agent is connected and authenticated
    virtual bool IsConnected() const = 0;
};

// Factory function to create platform-specific sender
std::unique_ptr<ITelemetrySender> CreateTelemetrySender();

} // namespace kinnector::ipc

#endif // KINNECTOR_IPC_H
