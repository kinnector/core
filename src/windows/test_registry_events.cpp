#include "etw_consumer.h"
#include <windows.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>
#include <string>
#include <algorithm>
#include <cctype>

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

bool EndsWithIgnoreCase(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin(),
                       [](char a, char b) { return tolower(a) == tolower(b); });
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

} // namespace

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            consumer.Stop(); \
            if (hkey) RegCloseKey(hkey); \
            RegDeleteKeyW(HKEY_CURRENT_USER, subkey.c_str()); \
            return 1; \
        } \
    } while (0)

static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows Registry Events (SetValueKey write) Test ===" << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not running elevated (Administrator) - "
                     "real Kernel-Registry ETW tracing requires it. "
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

    DWORD pid = GetCurrentProcessId();
    std::wstring subkey = L"Software\\KinnectorCoreTest_" + std::to_wstring(pid);
    std::string subkey_narrow = "KinnectorCoreTest_" + std::to_string(pid);
    HKEY hkey = nullptr;

    RegDeleteKeyW(HKEY_CURRENT_USER, subkey.c_str());

    std::cout << "[Test] Creating scratch HKCU key..." << std::endl;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0,
                               KEY_ALL_ACCESS, nullptr, &hkey, nullptr);
    CHECK(rc == ERROR_SUCCESS, "RegCreateKeyExW succeeded");

    std::cout << "[Test] Setting value..." << std::endl;
    const wchar_t* data = L"kinnector_registry_test_value";
    rc = RegSetValueExW(hkey, L"TestValue", 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(data),
                         static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t)));
    CHECK(rc == ERROR_SUCCESS, "RegSetValueExW succeeded");

    TelemetryEvent write_ev{};
    bool got_write = WaitForEvent(EventType::RegistryWrite, [&](const TelemetryEvent& ev) {
        return EndsWithIgnoreCase(ev.details.registry_write.key_path, subkey_narrow) &&
               std::string(ev.details.registry_write.value_name) == "TestValue";
    }, &write_ev, 5000);
    CHECK(got_write, "RegistryWrite event observed for the set value");
    CHECK(std::string(write_ev.details.registry_write.value_data).find("REG_SZ") == 0,
          "value_data summary correctly identifies the REG_SZ type");
    std::cout << "[Test] RegistryWrite: key_path=" << write_ev.details.registry_write.key_path
              << " value_name=" << write_ev.details.registry_write.value_name
              << " value_data=" << write_ev.details.registry_write.value_data << std::endl;

    consumer.Stop();
    RegCloseKey(hkey);
    RegDeleteKeyW(HKEY_CURRENT_USER, subkey.c_str());

    std::cout << "\n>>> TEST SUCCESSFUL! Registry write telemetry validated. <<<" << std::endl;
    return 0;
}
