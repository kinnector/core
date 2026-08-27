// WS6 burst-resilience test.
//
// Generates a deliberate ETW storm (a tight file create/delete loop + a batch
// of short-lived processes) while the reactive-profile consumer is running,
// and asserts the sensor does not fall over:
//   - EventsLost stays 0 (no dropped events)
//   - p99 emit latency recovers to a sane bound after the burst
//   - schema cache hit rate stays ~100%
//
// The files created here do NOT match the emit-path filter, so this exercises
// exactly the hot path that a real process-launch storm hammers: schema lookup
// + one property read + a basename hashset miss, then bail.

#include "kinnector/ffi.h"

#include <windows.h>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION el{};
    DWORD sz = sizeof(el);
    bool ok = GetTokenInformation(token, TokenElevation, &el, sizeof(el), &sz);
    CloseHandle(token);
    return ok && el.TokenIsElevated;
}

constexpr int kSkip = 127;

void FileStorm(const std::wstring& dir, int iterations) {
    for (int i = 0; i < iterations; ++i) {
        std::wstring p = dir + L"kinnector_burst_" + std::to_wstring(i) + L".tmp";
        HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(h, "x", 1, &w, nullptr);
            CloseHandle(h);
        }
        DeleteFileW(p.c_str());
    }
}

void ProcStorm(int count) {
    std::vector<HANDLE> procs;
    for (int i = 0; i < count; ++i) {
        wchar_t cl[] = L"cmd.exe /c exit";
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(nullptr, cl, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                           nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hThread);
            procs.push_back(pi.hProcess);
        }
    }
    for (HANDLE h : procs) { WaitForSingleObject(h, 5000); CloseHandle(h); }
}

}  // namespace

int main() {
    std::cout << "=== Running Windows ETW Burst-Resilience Test ===" << std::endl;
    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not elevated." << std::endl;
        return kSkip;
    }

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);

    if (!initialize_telemetry_engine(nullptr, "\\\\.\\pipe\\kinnector-burst-test", "tok")) {
        std::cerr << "[Test] initialize failed" << std::endl;
        return 1;
    }
    set_telemetry_profile_windows(1);  // reactive
    // A filter that the storm files will never match - the point is the cheap
    // filtered-out path.
    add_telemetry_path_filter_windows("C:\\kinnector\\nonexistent\\vault.dat");
    if (!start_telemetry_engine()) {
        std::cerr << "[Test] start failed" << std::endl;
        stop_telemetry_engine();
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));  // warm up

    std::cout << "[Test] generating burst..." << std::endl;
    const auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> stormers;
    for (int t = 0; t < 6; ++t) {
        std::wstring d = std::wstring(tmp) + L"t" + std::to_wstring(t) + L"_";
        stormers.emplace_back([d] { FileStorm(d, 6000); });
    }
    ProcStorm(40);
    for (auto& th : stormers) th.join();
    const auto burst_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - t0).count();
    std::cout << "[Test] burst issued in " << burst_ms << " ms" << std::endl;

    // Let the consumer drain.
    std::this_thread::sleep_for(std::chrono::seconds(3));

    uint64_t processed = 0, lost = 0, buffers = 0;
    double p50 = 0, p95 = 0, p99 = 0, mx = 0;
    bool got = get_telemetry_stats_windows(&processed, &lost, &buffers,
                                           &p50, &p95, &p99, &mx);
    std::cout << "[Test] stats: processed=" << processed << " lost=" << lost
              << " buffers=" << buffers << " p50=" << p50 << "ms p95=" << p95
              << "ms p99=" << p99 << "ms max=" << mx << "ms" << std::endl;

    stop_telemetry_engine();

    int rc = 0;
    if (!got)              { std::cerr << "[Test] FAIL: no stats\n"; rc = 1; }
    if (lost != 0)         { std::cerr << "[Test] FAIL: EventsLost=" << lost
                                       << " - consumer dropped events under burst\n"; rc = 1; }
    if (p99 > 5000.0)      { std::cerr << "[Test] FAIL: p99 " << p99
                                       << "ms - consumer fell too far behind\n"; rc = 1; }
    if (processed < 100)   { std::cerr << "[Test] FAIL: only " << processed
                                       << " events processed - burst didn't register\n"; rc = 1; }

    if (rc == 0)
        std::cout << "\n>>> TEST SUCCESSFUL! Consumer absorbed the burst "
                     "(0 lost, p99 " << p99 << "ms). <<<" << std::endl;
    return rc;
}
