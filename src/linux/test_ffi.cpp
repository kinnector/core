#include "kinnector/ffi.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <thread>
#include <atomic>
#include <chrono>

void TestFFILifecycleAndAPI() {
    std::cout << "[TestFFI] Testing FFI Lifecycle and C API exports..." << std::endl;

    // Before initialization or running, helper APIs should return false
    assert(add_sensitive_inode(1, 1, 1) == false);
    assert(add_protected_static_inode(1, 2) == false);
    assert(remove_protected_static_inode(1, 2) == false);
    assert(add_bypassed_directory_inode(1, 3) == false);
    assert(remove_bypassed_directory_inode(1, 3) == false);
    assert(add_trusted_exec_inode(4, 1) == false);
    assert(is_trusted_exec_inode(4) == false);
    assert(set_config_value(0, 100) == false);
    assert(update_process_threshold(1000, 2000ULL, 1) == false);
    assert(update_map_entry(0, 1000, 2000ULL, 1) == false);
    assert(delete_map_entry(0, 1000, 2000ULL) == false);
    assert(is_lsm_active() == false);
    assert(send_telemetry_event(nullptr) == false);

    // Setup a dummy unix socket for FFI IPC to connect without blocking
    std::string sock_path = "/tmp/test_kinnector_ffi.sock";
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

    // Also setup mock tty socket so start_telemetry_engine doesn't complain
    std::string tty_sock_path = "/var/run/kinnector/tty_telemetry.sock";
    // Note: if /var/run/kinnector is not writable or created, start_telemetry_engine just logs warning and continues.

    // Initialize in mock eBPF mode
    bool init_res = initialize_telemetry_engine("/path/to/nonexistent/bpf.o", sock_path.c_str(), "test-token");
    assert(init_res == true);

    // Double initialize should return false
    assert(initialize_telemetry_engine("/path/to/nonexistent/bpf.o", sock_path.c_str(), "test-token") == false);

    // Start engine
    bool start_res = start_telemetry_engine();
    assert(start_res == true);

    // Double start should return false
    assert(start_telemetry_engine() == false);

    // Now that engine is running (`g_running == true`), test all map and helper FFI exports
    assert(add_sensitive_inode(1, 1001, 1) == true);
    assert(add_protected_static_inode(1, 1002) == true);
    assert(remove_protected_static_inode(1, 1002) == true);
    assert(add_bypassed_directory_inode(1, 1003) == true);
    assert(remove_bypassed_directory_inode(1, 1003) == true);
    assert(add_trusted_exec_inode(1004, 5) == true);
    assert(is_trusted_exec_inode(1004) == false); // Mock mode returns false or lookup status
    assert(set_config_value(0, 42) == true);
    assert(update_process_threshold(5555, 123456ULL, 2) == true);
    assert(update_map_entry(0, 5555, 123456ULL, 1) == true);
    assert(delete_map_entry(0, 5555, 123456ULL) == true);
    assert(is_lsm_active() == false); // Mock mode

    TelemetryEvent ev{};
    ev.header.event_type = EventType::ProcessCreate;
    ev.header.pid = 9999;
    // Sending event should return true if connected or false if not connected yet (socket handshake might be pending)
    send_telemetry_event(&ev);

    stop_telemetry_engine();
    // Double stop should not crash
    stop_telemetry_engine();

    close(server_fd);
    unlink(sock_path.c_str());
    std::cout << "  - FFI lifecycle and API functions tested successfully." << std::endl;
}

int main() {
    std::cout << "==========================================\n";
    std::cout << "=== Running FFI Interface Test Suite =====\n";
    std::cout << "==========================================\n";
    TestFFILifecycleAndAPI();
    std::cout << "\n>>> FFI INTERFACE TEST PASSED successfully! <<<\n";
    return 0;
}
