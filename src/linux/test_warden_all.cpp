#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <sys/wait.h>
#include <iomanip>

struct TestResult {
    std::string name;
    bool passed;
    double duration_ms;
    int exit_code;
};

std::string GetExeDir() {
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) {
        return ".";
    }
    path[len] = '\0';
    return std::string(dirname(path));
}

int main(int argc, char* argv[]) {
    std::cout << "=================================================================\n";
    std::cout << "=== KINNECTOR CORE (@core/) WARDEN LINUX COMPLETE TEST SUITE ===\n";
    std::cout << "=================================================================\n\n";

    std::string bin_dir = GetExeDir();
    std::cout << "[TestOrchestrator] Discovered binary directory: " << bin_dir << "\n";
    if (getuid() == 0) {
        std::cout << "[TestOrchestrator] Running with ROOT permissions (Live eBPF & Fanotify enabled)\n\n";
    } else {
        std::cout << "[TestOrchestrator] Running with USER permissions (Fallback/Mock & IPC/Structs verified)\n";
        std::cout << "                   Tip: Run with 'sudo' to also execute live kernel eBPF/LSM tests.\n\n";
    }

    std::vector<std::string> test_binaries = {
        "kinnector-test-telemetry",
        "kinnector-test-warden-helper",
        "kinnector-test-fanotify",
        "kinnector-test-ebpf-loader",
        "kinnector-test-linux-ipc",
        "kinnector-test-ffi",
        "kinnector-test-ipc",
        "kinnector-test-lsm"
    };

    std::vector<TestResult> results;
    int total_passed = 0;
    int total_failed = 0;

    for (const auto& bin_name : test_binaries) {
        std::string full_path = bin_dir + "/" + bin_name;
        if (access(full_path.c_str(), X_OK) != 0) {
            std::cerr << "[TestOrchestrator] Warning: Test binary not found or not executable: " << full_path << "\n";
            results.push_back({bin_name, false, 0.0, -1});
            total_failed++;
            continue;
        }

        std::cout << "-----------------------------------------------------------------\n";
        std::cout << ">>> Executing Test Target: " << bin_name << "\n";
        std::cout << "-----------------------------------------------------------------\n";

        auto start_time = std::chrono::high_resolution_clock::now();
        int status = system(full_path.c_str());
        auto end_time = std::chrono::high_resolution_clock::now();

        double duration_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        int exit_code = -1;
        bool passed = false;

        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            passed = (exit_code == 0);
        }

        if (passed) {
            total_passed++;
            std::cout << "\n[RESULT] " << bin_name << " -> PASSED (" << std::fixed << std::setprecision(2) << duration_ms << " ms)\n\n";
        } else {
            total_failed++;
            std::cout << "\n[RESULT] " << bin_name << " -> FAILED (Exit Code: " << exit_code << ", " << std::fixed << std::setprecision(2) << duration_ms << " ms)\n\n";
        }

        results.push_back({bin_name, passed, duration_ms, exit_code});
    }

    std::cout << "=================================================================\n";
    std::cout << "=== SUMMARY OF KINNECTOR CORE (@core/) WARDEN LINUX TEST SUITE ===\n";
    std::cout << "=================================================================\n";
    std::cout << std::left << std::setw(32) << "Test Suite" << std::setw(12) << "Status" << std::setw(14) << "Duration (ms)" << "Exit Code\n";
    std::cout << "-----------------------------------------------------------------\n";

    for (const auto& res : results) {
        std::string status_str = res.passed ? "PASSED" : "FAILED";
        std::cout << std::left << std::setw(32) << res.name 
                  << std::setw(12) << status_str 
                  << std::setw(14) << std::fixed << std::setprecision(2) << res.duration_ms 
                  << res.exit_code << "\n";
    }
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "Total Passed: " << total_passed << " / " << results.size() << "\n";
    std::cout << "Total Failed: " << total_failed << " / " << results.size() << "\n";
    std::cout << "=================================================================\n";

    return (total_failed == 0) ? 0 : 1;
}
