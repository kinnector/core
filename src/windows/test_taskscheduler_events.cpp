#include "etw_consumer.h"
#include <windows.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>
#include <string>

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

template <typename Pred>
bool WaitForEvent(EventType type, Pred pred, TelemetryEvent* out, int timeout_ms) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
        for (const auto& ev : g_events) {
            if (ev.header.event_type == type && pred(ev)) {
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

// schtasks.exe does the actual registration - runs it as a child process and
// waits for it to exit (this test needs the *real* Task Scheduler service to
// process the request, not a mock, per core/CLAUDE.md's real-kernel-path
// testing discipline).
bool RunSchtasks(const std::wstring& args) {
    std::wstring cmdline = L"schtasks.exe " + args;
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
    buf.push_back(0);
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exit_code == 0;
}

} // namespace

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            consumer.Stop(); \
            RunSchtasks(L"/Delete /TN " + task_name + L" /F"); \
            return 1; \
        } \
    } while (0)

static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows TaskScheduler Events (TaskRegistered) Test ===" << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not running elevated (Administrator) - "
                     "real TaskScheduler ETW tracing (and schtasks.exe /Create) "
                     "requires it. Re-run this test from an elevated session to "
                     "actually validate it."
                  << std::endl;
        return kSkipReturnCode;
    }

    DWORD pid = GetCurrentProcessId();
    std::wstring task_name = L"KinnectorCoreTestTask_" + std::to_wstring(pid);
    std::string task_name_narrow_suffix = "KinnectorCoreTestTask_" + std::to_string(pid);

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

    RunSchtasks(L"/Delete /TN " + task_name + L" /F"); // clear any leftover

    std::cout << "[Test] Registering a real scheduled task via schtasks.exe..." << std::endl;
    bool created = RunSchtasks(L"/Create /TN " + task_name +
                                L" /TR \"cmd.exe /c ver\" /SC ONCE /ST 23:59 /F");
    CHECK(created, "schtasks.exe /Create succeeded");

    TelemetryEvent reg_ev{};
    bool got_reg = WaitForEvent(EventType::TaskRegistered, [&](const TelemetryEvent& ev) {
        std::string name = ev.details.task_registered.task_name;
        return name.find(task_name_narrow_suffix) != std::string::npos;
    }, &reg_ev, 5000);
    CHECK(got_reg, "TaskRegistered event observed for the real schtasks.exe /Create");
    std::cout << "[Test] TaskRegistered: task_name=" << reg_ev.details.task_registered.task_name
              << " user_context=" << reg_ev.details.task_registered.user_context << std::endl;

    consumer.Stop();
    RunSchtasks(L"/Delete /TN " + task_name + L" /F");

    std::cout << "\n>>> TEST SUCCESSFUL! TaskScheduler registration telemetry validated. <<<" << std::endl;
    return 0;
}
