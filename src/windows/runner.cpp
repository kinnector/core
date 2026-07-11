#include "kinnector/ffi.h"
#include "kinnector/telemetry.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <cstring>

int main() {
    std::cout << "=== Kinnector Core Telemetry Runner (Windows) ===" << std::endl;

    const char* socket_path = "\\\\.\\pipe\\kinnector-telemetry";
    const char* auth_token = "super-secret-agent-token-12345";

    std::cout << "[Runner] Initializing telemetry engine..." << std::endl;
    if (!initialize_telemetry_engine(nullptr, socket_path, auth_token)) {
        std::cerr << "[Runner] Error: failed to initialize telemetry engine" << std::endl;
        return 1;
    }

    std::cout << "[Runner] Starting telemetry engine..." << std::endl;
    if (!start_telemetry_engine()) {
        std::cerr << "[Runner] Error: failed to start telemetry engine" << std::endl;
        return 1;
    }

    std::cout << "[Runner] Waiting for IPC connection to establish..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // 1. Send ProcessCreate event
    std::cout << "[Runner] Sending ProcessCreate event..." << std::endl;
    TelemetryEvent pc_event = {};
    pc_event.header.sequence_number = 1;
    pc_event.header.timestamp_ns = 1000000000;
    pc_event.header.pid = 999;
    pc_event.header.event_type = EventType::ProcessCreate;
    pc_event.header.source = TelemetrySource::ETW;

    pc_event.details.process_create.child_pid = 12345;
    pc_event.details.process_create.real_parent_pid = 999;
    std::strncpy(pc_event.details.process_create.child_image_path, "C:\\Windows\\System32\\cmd.exe", sizeof(pc_event.details.process_create.child_image_path));
    std::strncpy(pc_event.details.process_create.child_command_line, "cmd.exe /c echo Hello", sizeof(pc_event.details.process_create.child_command_line));

    if (send_telemetry_event(&pc_event)) {
        std::cout << "[Runner] ProcessCreate event sent successfully." << std::endl;
    } else {
        std::cerr << "[Runner] Warning: failed to send ProcessCreate event (is agent running?)" << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // 2. Send FileWrite event inside protected directory
    std::cout << "[Runner] Sending FileWrite event to hijack wallet..." << std::endl;
    TelemetryEvent fw_event = {};
    fw_event.header.sequence_number = 2;
    fw_event.header.timestamp_ns = 2000000000;
    fw_event.header.pid = 12345;
    fw_event.header.event_type = EventType::FileWrite;
    fw_event.header.source = TelemetrySource::ETW;

    fw_event.details.file_write.bytes_written = 100;
    std::strncpy(fw_event.details.file_write.file_path, "C:\\Users\\user\\exodus\\wallet.json", sizeof(fw_event.details.file_write.file_path));

    if (send_telemetry_event(&fw_event)) {
        std::cout << "[Runner] FileWrite event sent successfully." << std::endl;
    } else {
        std::cerr << "[Runner] Warning: failed to send FileWrite event" << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << "[Runner] Stopping telemetry engine..." << std::endl;
    stop_telemetry_engine();

    std::cout << "[Runner] Done!" << std::endl;
    return 0;
}
