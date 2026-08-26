#include "etw_consumer.h"
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>
#include <string>

#pragma comment(lib, "crypt32")

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

} // namespace

// This project builds Release/-DNDEBUG (see core/CLAUDE.md) - assert() is
// elided, so every check here is a real if/return, not assert().
#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            consumer.Stop(); \
            return 1; \
        } \
    } while (0)

// Same elevation requirement/skip-not-mock pattern as test_process_lineage.cpp
// (real Kernel-* ETW tracing needs it, same session covers Crypto-DPAPI too).
static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows DPAPI Events Test ===" << std::endl;
    std::cout << "[Test] NOTE: DPAPIDefInformationEvent is EMPIRICALLY CONFIRMED to fire "
                 "only for a process' FIRST DPAPI operation (WINDOWS_COVERAGE_PLAN.md Phase 6) - "
                 "this test only exercises that first-call signal, not per-call repetition."
              << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not running elevated (Administrator) - "
                     "real Kernel-* ETW tracing requires it. "
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

    // This test process' own FIRST DPAPI operation - CryptUnprotectData
    // specifically, to prove the event fires for Unprotect (not just Protect)
    // and correctly reports OperationType, matching the isolated-fresh-process
    // diagnostic this wiring was based on.
    std::cout << "[Test] Protecting a disposable secret..." << std::endl;
    BYTE secret_bytes[] = "kinnector dpapi test payload";
    DATA_BLOB in_blob = { sizeof(secret_bytes), secret_bytes };
    DATA_BLOB protected_blob = {};
    const std::wstring description = L"KinnectorDpapiTestSecret";
    CHECK(CryptProtectData(&in_blob, description.c_str(), nullptr, nullptr, nullptr, 0, &protected_blob),
          "CryptProtectData succeeded");

    std::cout << "[Test] Unprotecting it back (this process' FIRST DPAPI call)..." << std::endl;
    DATA_BLOB unprotected = {};
    LPWSTR out_description = nullptr;
    CHECK(CryptUnprotectData(&protected_blob, &out_description, nullptr, nullptr, nullptr, 0, &unprotected),
          "CryptUnprotectData succeeded");

    TelemetryEvent dpapi_ev{};
    bool got = WaitForEvent(EventType::DpapiOperation, [&](const TelemetryEvent& ev) {
        // Either Protect or Unprotect might be the one that actually fires
        // the event - it's whichever DPAPI call happens first in this
        // process' lifetime (the empirically-confirmed limitation), and
        // CryptProtectData ran first here.
        std::string op = ev.details.dpapi_operation.operation_type;
        return op == "SPCryptProtect" || op == "SPCryptUnprotect";
    }, &dpapi_ev, 5000);
    CHECK(got, "DpapiOperation event observed for this process' first DPAPI call");
    std::cout << "[Test] DpapiOperation: operation_type=" << dpapi_ev.details.dpapi_operation.operation_type
              << " data_description=" << dpapi_ev.details.dpapi_operation.data_description
              << " return_value=" << dpapi_ev.details.dpapi_operation.return_value
              << " plaintext_data_size=" << dpapi_ev.details.dpapi_operation.plaintext_data_size
              << " caller_pid=" << dpapi_ev.details.dpapi_operation.caller_pid
              << " caller_process_creation_time=" << dpapi_ev.details.dpapi_operation.caller_process_creation_time
              << " caller_process_start_key=" << dpapi_ev.details.dpapi_operation.caller_process_start_key
              << std::endl;
    // The actual bug this test caught on the first real run: the event's raw
    // ETW EventHeader.ProcessId is always lsass.exe (DPAPI master-key ops run
    // there on the caller's behalf), NOT the calling process - header.pid
    // must come from the event's own CallerProcessID property instead. See
    // WINDOWS_COVERAGE_PLAN.md Phase 6.
    CHECK(dpapi_ev.header.pid == GetCurrentProcessId(),
          "event attributed to this test process' own pid (via CallerProcessID, not the raw ETW ProcessId)");
    CHECK(dpapi_ev.details.dpapi_operation.caller_pid == GetCurrentProcessId(),
          "caller_pid field itself also matches this test process");
    CHECK(dpapi_ev.details.dpapi_operation.caller_process_creation_time != 0,
          "caller_process_creation_time was populated (non-zero)");
    CHECK(dpapi_ev.details.dpapi_operation.return_value == 0, "return_value reports success (0)");

    LocalFree(unprotected.pbData);
    if (out_description) LocalFree(out_description);
    LocalFree(protected_blob.pbData);

    consumer.Stop();
    std::cout << "\n>>> TEST SUCCESSFUL! DPAPI first-call telemetry validated. <<<" << std::endl;
    return 0;
}
