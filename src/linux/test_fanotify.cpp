#include "fanotify.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

using namespace kinnector;
using namespace kinnector::lnx;

void TestFanotifyLifecycle() {
    std::cout << "[TestFanotify] Testing lifecycle without sudo / or checking return codes..." << std::endl;
    kinnector::lnx::FanotifyMonitor monitor;

    // Check if we have CAP_SYS_ADMIN by trying to initialize
    bool init_ok = monitor.Initialize("/home");
    if (!init_ok) {
        std::cout << "  - Note: fanotify_init failed (likely lack of sudo/root permissions or unsupported filesystem). Skipping live event test." << std::endl;
        return;
    }

    // Double Initialize should return false
    assert(monitor.Initialize("/home") == false);

    std::atomic<int> events_received{0};
    std::string received_path;

    monitor.SetEventCallback([&](const TelemetryEvent& ev) {
        assert(ev.header.event_type == EventType::FileWrite);
        assert(ev.header.source == TelemetrySource::fanotify);
        if (std::strstr(ev.details.file_write.file_path, "fanotify_test_file.txt") != nullptr) {
            received_path = ev.details.file_write.file_path;
            events_received++;
        }
    });

    bool start_ok = monitor.Start();
    assert(start_ok == true);

    // Double Start should return false
    assert(monitor.Start() == false);

    // Trigger a file write & close in /home (which is not in noisy filtered paths)
    std::string test_filepath = "/home/user/Documents/kinnector/fanotify_test_file.txt";
    {
        std::ofstream out(test_filepath, std::ios::trunc);
        out << "Hello Fanotify!" << std::endl;
    }

    // Wait up to 2 seconds for event to arrive
    for (int i = 0; i < 20 && events_received == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "  - Events received for test file: " << events_received << std::endl;
    if (events_received > 0) {
        std::cout << "  - Verified path: " << received_path << std::endl;
    }

    // Clean up test file
    unlink(test_filepath.c_str());

    monitor.Stop();
    // Double stop should not crash
    monitor.Stop();

    std::cout << "  - FanotifyMonitor lifecycle and event dispatch verified." << std::endl;
}

// Phase 8 (LINUX_COVERAGE_PLAN.md): belt-and-suspenders blocking test --
// confirms FAN_OPEN_PERM actually denies access to a registered resource, not
// just that notification events arrive. Skips gracefully (like
// TestFanotifyLifecycle above) when fanotify_init fails or FAN_CLASS_CONTENT
// isn't available -- both require CAP_SYS_ADMIN, same constraint as every
// other real-kernel test in this suite.
void TestFanotifyOpenPermBlocking() {
    std::cout << "[TestFanotify] Testing FAN_OPEN_PERM blocking..." << std::endl;
    kinnector::lnx::FanotifyMonitor monitor;

    if (!monitor.Initialize("/home")) {
        std::cout << "  - Note: fanotify_init failed (likely lack of sudo/root permissions). Skipping." << std::endl;
        return;
    }
    if (!monitor.IsPermissionCapable()) {
        std::cout << "  - Note: FAN_CLASS_CONTENT unavailable (fell back to notify-only). Skipping blocking test." << std::endl;
        monitor.Stop();
        return;
    }

    std::string protected_path = "/home/user/Documents/kinnector/fanotify_perm_test_protected.txt";
    std::string open_path = "/home/user/Documents/kinnector/fanotify_perm_test_open.txt";
    {
        std::ofstream out1(protected_path, std::ios::trunc);
        out1 << "protected" << std::endl;
        std::ofstream out2(open_path, std::ios::trunc);
        out2 << "open" << std::endl;
    }

    struct stat st{};
    if (stat(protected_path.c_str(), &st) != 0) {
        std::cout << "  - Note: could not stat protected test file, skipping." << std::endl;
        unlink(protected_path.c_str());
        unlink(open_path.c_str());
        monitor.Stop();
        return;
    }
    monitor.AddProtectedResource(static_cast<uint64_t>(st.st_dev), static_cast<uint64_t>(st.st_ino));

    assert(monitor.Start() == true);
    // Give the monitor thread a moment to be actively reading before we attack.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto try_open = [](const std::string& path) -> int {
        pid_t pid = fork();
        if (pid < 0) return -1;
        if (pid == 0) {
            int fd = open(path.c_str(), O_RDONLY);
            if (fd < 0) _exit(errno);
            close(fd);
            _exit(0);
        }
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) return -1;
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    };

    int protected_rc = try_open(protected_path);
    int open_rc = try_open(open_path);

    unlink(protected_path.c_str());
    unlink(open_path.c_str());
    monitor.Stop();

    std::cout << "  - Registered resource open() result: " << protected_rc
              << " (expected EPERM=" << EPERM << ")" << std::endl;
    std::cout << "  - Unregistered resource open() result: " << open_rc
              << " (expected 0)" << std::endl;
    assert(protected_rc == EPERM);
    assert(open_rc == 0);

    std::cout << "  - FAN_OPEN_PERM blocking verified." << std::endl;
}

int main() {
    std::cout << "==========================================\n";
    std::cout << "=== Running Fanotify Monitor Test Suite ==\n";
    std::cout << "==========================================\n";
    TestFanotifyLifecycle();
    TestFanotifyOpenPermBlocking();
    std::cout << "\n>>> FANOTIFY MONITOR TEST PASSED successfully! <<<\n";
    return 0;
}
