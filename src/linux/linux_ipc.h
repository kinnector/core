#ifndef KINNECTOR_LINUX_IPC_H
#define KINNECTOR_LINUX_IPC_H

#include "kinnector/ipc.h"
#include <atomic>
#include <thread>
#include <mutex>

namespace kinnector::ipc::lnx {

class LinuxTelemetrySender : public ITelemetrySender {
public:
    LinuxTelemetrySender();
    ~LinuxTelemetrySender() override;

    bool Start(const IPCConfig& config) override;
    void Stop() override;
    bool SendEvent(const TelemetryEvent& event) override;
    bool IsConnected() const override;

private:
    void ConnectionLoop();
    bool PerformHandshake(int fd);

    IPCConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<int> socket_fd_{-1};
    std::thread connection_thread_;
    std::mutex send_mutex_;
};

} // namespace kinnector::ipc::lnx

#endif // KINNECTOR_LINUX_IPC_H
