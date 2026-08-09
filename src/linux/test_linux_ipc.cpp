#include "linux_ipc.h"
#include "kinnector/ipc.h"
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>

void TestFactoryAndOfflineSend() {
    std::cout << "[TestLinuxIPC] Testing factory and offline sending..." << std::endl;
    auto sender = kinnector::ipc::CreateTelemetrySender();
    assert(sender != nullptr);
    assert(sender->IsConnected() == false);

    TelemetryEvent ev{};
    ev.header.event_type = EventType::ProcessCreate;
    assert(sender->SendEvent(ev) == false);
    std::cout << "  - Factory and offline verification passed." << std::endl;
}

void TestInsecureSocketPermissions() {
    std::cout << "[TestLinuxIPC] Testing insecure socket permission rejection..." << std::endl;
    std::string sock_path = "/tmp/test_kinnector_insecure.sock";
    unlink(sock_path.c_str());

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(server_fd >= 0);

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    assert(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    assert(listen(server_fd, 5) == 0);

    // Set insecure permissions (e.g. 0666 - group and world writable)
    chmod(sock_path.c_str(), 0666);

    auto sender = kinnector::ipc::CreateTelemetrySender();
    kinnector::ipc::IPCConfig cfg;
    cfg.socket_path = sock_path;
    cfg.auth_token = "secret";

    assert(sender->Start(cfg) == true);

    // Give it a moment to attempt connection and reject due to permissions
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    assert(sender->IsConnected() == false);

    sender->Stop();
    close(server_fd);
    unlink(sock_path.c_str());
    std::cout << "  - Insecure socket permissions rejected as expected." << std::endl;
}

void TestSuccessfulHandshakeAndTransmission() {
    std::cout << "[TestLinuxIPC] Testing secure socket connection, handshake, and transmission..." << std::endl;
    std::string sock_path = "/tmp/test_kinnector_secure.sock";
    unlink(sock_path.c_str());

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(server_fd >= 0);

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    assert(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    assert(listen(server_fd, 5) == 0);

    // Enforce secure permissions (0600 - user read/write only)
    chmod(sock_path.c_str(), 0600);

    std::atomic<bool> server_finished{false};
    std::thread server_thread([&]() {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) return;

        // Read token len
        uint32_t token_len = 0;
        if (read(client_fd, &token_len, sizeof(token_len)) != sizeof(token_len)) {
            close(client_fd);
            return;
        }

        std::string token(token_len, '\0');
        if (read(client_fd, &token[0], token_len) != static_cast<ssize_t>(token_len)) {
            close(client_fd);
            return;
        }
        assert(token == "secret-token-42");

        // Send auth success status (1)
        uint8_t status = 1;
        write(client_fd, &status, sizeof(status));

        // Read transmitted telemetry event
        TelemetryEvent received_ev{};
        ssize_t bytes_read = read(client_fd, &received_ev, sizeof(received_ev));
        assert(bytes_read == sizeof(received_ev));
        assert(received_ev.header.event_type == EventType::NetworkConnect);
        assert(received_ev.header.pid == 9876);
        assert(std::strcmp(received_ev.details.network_connect.protocol, "TCP") == 0);

        close(client_fd);
        server_finished = true;
    });

    auto sender = kinnector::ipc::CreateTelemetrySender();
    kinnector::ipc::IPCConfig cfg;
    cfg.socket_path = sock_path;
    cfg.auth_token = "secret-token-42";

    assert(sender->Start(cfg) == true);
    assert(sender->Start(cfg) == false); // Double start

    // Wait for connection to succeed
    for (int i = 0; i < 20 && !sender->IsConnected(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    assert(sender->IsConnected() == true);

    TelemetryEvent ev{};
    ev.header.event_type = EventType::NetworkConnect;
    ev.header.pid = 9876;
    std::strncpy(ev.details.network_connect.protocol, "TCP", sizeof(ev.details.network_connect.protocol) - 1);

    assert(sender->SendEvent(ev) == true);

    if (server_thread.joinable()) {
        server_thread.join();
    }
    assert(server_finished == true);

    sender->Stop();
    sender->Stop(); // Double stop
    close(server_fd);
    unlink(sock_path.c_str());
    std::cout << "  - Handshake and transmission verified successfully." << std::endl;
}

void TestFailedHandshake() {
    std::cout << "[TestLinuxIPC] Testing rejected handshake (server sends status=0)..." << std::endl;
    std::string sock_path = "/tmp/test_kinnector_reject.sock";
    unlink(sock_path.c_str());

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(server_fd >= 0);

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    assert(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    assert(listen(server_fd, 5) == 0);
    chmod(sock_path.c_str(), 0600);

    std::thread server_thread([&]() {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) return;

        uint32_t token_len = 0;
        if (read(client_fd, &token_len, sizeof(token_len)) == sizeof(token_len)) {
            std::string token(token_len, '\0');
            read(client_fd, &token[0], token_len);
        }

        // Send auth failure status (0)
        uint8_t status = 0;
        write(client_fd, &status, sizeof(status));
        close(client_fd);
    });

    auto sender = kinnector::ipc::CreateTelemetrySender();
    kinnector::ipc::IPCConfig cfg;
    cfg.socket_path = sock_path;
    cfg.auth_token = "invalid-token";

    sender->Start(cfg);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    assert(sender->IsConnected() == false);

    sender->Stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
    close(server_fd);
    unlink(sock_path.c_str());
    std::cout << "  - Handshake rejection verified successfully." << std::endl;
}

int main() {
    std::cout << "==========================================\n";
    std::cout << "=== Running Linux IPC Test Suite =========\n";
    std::cout << "==========================================\n";
    TestFactoryAndOfflineSend();
    TestInsecureSocketPermissions();
    TestSuccessfulHandshakeAndTransmission();
    TestFailedHandshake();
    std::cout << "\n>>> LINUX IPC TEST PASSED successfully! <<<\n";
    return 0;
}
