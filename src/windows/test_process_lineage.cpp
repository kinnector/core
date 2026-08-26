#include "etw_consumer.h"
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>

using kinnector::windows::EtwConsumer;

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::vector<TelemetryEvent> g_events;

void OnEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.push_back(event);
    g_cv.notify_all();
}

bool WaitForMatchingChild(DWORD child_pid, TelemetryEvent* out, int timeout_ms) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
        for (const auto& ev : g_events) {
            if (ev.header.event_type == EventType::ProcessCreate &&
                ev.details.process_create.child_pid == child_pid) {
                *out = ev;
                return true;
            }
        }
        return false;
    });
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

} // namespace

// This project builds Release/-DNDEBUG (see core/CLAUDE.md), which silently
// elides assert() - every correctness check here uses a real if/return
// instead, not assert().
#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            consumer.Stop(); \
            return 1; \
        } \
    } while (0)

// Real Kernel-Process ETW tracing needs Administrator (see WINDOWS_COVERAGE_PLAN.md).
// Per core/CLAUDE.md's warning about test_lsm/test_enforcement_e2e silently
// mock-falling-back on Linux when unprivileged: this test does NOT fall back
// to a mock. It explicitly reports "not elevated, skipped" via CTest's
// SKIP_RETURN_CODE (see CMakeLists.txt) rather than passing without proving
// anything.
static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows Process Lineage (ETW sequence-number) Test ===" << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not running elevated (Administrator) - "
                     "real Kernel-Process ETW tracing requires it. "
                     "Re-run this test from an elevated session to actually validate it."
                  << std::endl;
        return kSkipReturnCode;
    }

    EtwConsumer consumer;
    if (!consumer.Initialize()) {
        std::cerr << "[Test] EtwConsumer::Initialize failed even though elevated" << std::endl;
        return 1;
    }
    consumer.SetEventCallback(OnEvent);
    if (!consumer.Start()) {
        std::cerr << "[Test] EtwConsumer::Start failed" << std::endl;
        return 1;
    }

    std::cout << "[Test] Spawning a helper child process (cmd /c ver)..." << std::endl;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t cmdline[] = L"cmd.exe /c ver >nul";
    CHECK(CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi),
          "CreateProcess helper child");
    DWORD child_pid = pi.dwProcessId;
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    TelemetryEvent matched{};
    if (!WaitForMatchingChild(child_pid, &matched, 5000)) {
        std::cerr << "[Test] Timed out waiting for ProcessCreate event for pid "
                  << child_pid << std::endl;
        consumer.Stop();
        return 1;
    }

    CHECK(matched.details.process_create.child_pid == child_pid, "child_pid matches spawned process");
    CHECK(matched.details.process_create.real_parent_pid == GetCurrentProcessId(),
          "real_parent_pid matches this test process");
    CHECK(matched.details.process_create.child_sequence_number != 0,
          "child_sequence_number is non-zero (0 means 'not found' per telemetry.h contract)");
    CHECK(matched.details.process_create.parent_sequence_number != 0,
          "parent_sequence_number is non-zero");
    CHECK(matched.details.process_create.child_sequence_number !=
              matched.details.process_create.parent_sequence_number,
          "child and parent sequence numbers must differ");

    std::cout << "[Test] child_sequence_number=" << matched.details.process_create.child_sequence_number
              << " parent_sequence_number=" << matched.details.process_create.parent_sequence_number
              << std::endl;

    consumer.Stop();
    std::cout << "\n>>> TEST SUCCESSFUL! Process lineage sequence numbers validated. <<<" << std::endl;
    return 0;
}
