// WS7 (MVP_REACTIVE_PLAN.md) - oplock synchronous hold, end to end.
//
// Registers a protected file + an owner-signer allowlist that does NOT
// include the reader's vendor, arms a file guard on it, then has an
// unauthorized process open+read the file. Asserts the opener is SUSPENDED
// before it can complete the read (proved via a sentinel file the reader
// only writes *after* the read), then that resuming it lets the read finish
// (we paused, not killed), then that an authorized-signer reader is not held.
//
// The "reader" is just cmd.exe (Microsoft-signed; the allowlist is set to a
// different vendor). Nothing here reads a real credential store or
// exfiltrates anything.

#include "kinnector/ffi.h"

#include <windows.h>
#include <chrono>
#include <fstream>
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

HANDLE g_proc = nullptr;
std::wstring g_protected, g_sentinel1, g_sentinel2;

void cleanup() {
    if (g_proc) { TerminateProcess(g_proc, 0); CloseHandle(g_proc); g_proc = nullptr; }
    if (!g_protected.empty()) DeleteFileW(g_protected.c_str());
    if (!g_sentinel1.empty()) DeleteFileW(g_sentinel1.c_str());
    if (!g_sentinel2.empty()) DeleteFileW(g_sentinel2.c_str());
    stop_telemetry_engine();
}

#define CHECK(cond, msg)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" \
                      << std::endl;                                            \
            cleanup();                                                          \
            return 1;                                                          \
        }                                                                      \
    } while (0)

// cmd /c: read the file, THEN write the sentinel, THEN stay alive.
// If cmd is suspended during the CreateFile of `type`, the sentinel `echo`
// never runs.
HANDLE SpawnReader(const std::wstring& file, const std::wstring& sentinel,
                   DWORD* out_pid, DWORD* out_tid) {
    // Temp paths on this machine have no spaces, so no inner quoting needed
    // (nested cmd quoting is fragile). ping first -> cmd is definitely alive
    // when the read (the thing the guard must catch) happens.
    std::wstring cl = L"cmd.exe /c \"ping -n 2 127.0.0.1 >nul & type " + file +
                      L" >nul & echo done> " + sentinel +
                      L" & ping -n 60 127.0.0.1 >nul\"";
    std::vector<wchar_t> buf(cl.begin(), cl.end());
    buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return nullptr;
    *out_pid = pi.dwProcessId;
    *out_tid = pi.dwThreadId;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

bool IsThreadSuspended(DWORD tid) {
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) return false;
    DWORD prev = SuspendThread(th);
    if (prev != (DWORD)-1) ResumeThread(th);  // undo our probe
    CloseHandle(th);
    return prev != (DWORD)-1 && prev >= 1;
}

bool FileExists(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool ResolveFileId(const std::wstring& path, uint32_t* vol, uint64_t* frn) {
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION fi{};
    bool ok = GetFileInformationByHandle(h, &fi) != 0;
    CloseHandle(h);
    if (!ok) return false;
    *vol = fi.dwVolumeSerialNumber;
    *frn = (static_cast<uint64_t>(fi.nFileIndexHigh) << 32) | fi.nFileIndexLow;
    return true;
}

bool ResolveActor(DWORD pid, uint64_t* seq, uint64_t* ct, std::string* signer) {
    char img[512] = {}, sig[256] = {};
    uint8_t signed_ok = 0;
    if (!resolve_actor_windows(pid, seq, ct, img, sizeof(img), sig, sizeof(sig), &signed_ok))
        return false;
    *signer = sig;
    return true;
}

std::string Narrow(const std::wstring& w) {
    char b[1024];
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, b, sizeof(b), nullptr, nullptr);
    return std::string(b);
}

constexpr int kSkip = 127;

} // namespace

int main() {
    std::cout << "=== Running Windows File Guard (WS7) Test ===" << std::endl;
    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not elevated." << std::endl;
        return kSkip;
    }

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const auto pid_s = std::to_wstring(GetCurrentProcessId());
    g_protected = std::wstring(tmp) + L"kinnector_fg_vault_" + pid_s + L".dat";
    g_sentinel1 = std::wstring(tmp) + L"kinnector_fg_sentinel1_" + pid_s + L".txt";
    g_sentinel2 = std::wstring(tmp) + L"kinnector_fg_sentinel2_" + pid_s + L".txt";
    { std::ofstream f(g_protected, std::ios::binary); f << "dummy vault contents"; }
    DeleteFileW(g_sentinel1.c_str());
    DeleteFileW(g_sentinel2.c_str());

    if (!initialize_telemetry_engine(nullptr, "\\\\.\\pipe\\kinnector-fg-test", "tok")) {
        std::cerr << "[Test] initialize_telemetry_engine failed" << std::endl;
        cleanup();
        return 1;
    }
    set_telemetry_profile_windows(1);  // reactive profile
    if (!start_telemetry_engine()) {
        std::cerr << "[Test] start_telemetry_engine failed" << std::endl;
        cleanup();
        return 1;
    }
    // Let the ETW session + process registry warm up.
    std::this_thread::sleep_for(std::chrono::seconds(2));

    uint32_t vol = 0;
    uint64_t frn = 0;
    CHECK(ResolveFileId(g_protected, &vol, &frn), "resolved the protected file's (vol, frn)");

    CHECK(add_protected_resource_windows(vol, frn, 1), "add_protected_resource_windows");
    CHECK(add_resource_owner_signer_windows(vol, frn, "Some Unrelated Vendor LLC"),
          "add_resource_owner_signer_windows");

    const std::string narrow_path = Narrow(g_protected);
    add_telemetry_path_filter_windows(narrow_path.c_str());  // exercise the emit filter
    CHECK(add_file_guard_windows(narrow_path.c_str()), "add_file_guard_windows");
    CHECK(set_response_enforcement_windows(1), "armed response enforcement");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));  // oplock settles

    // ── unauthorized reader: must be suspended before the read completes ────
    DWORD pid = 0, tid = 0;
    g_proc = SpawnReader(g_protected, g_sentinel1, &pid, &tid);
    CHECK(g_proc != nullptr, "spawned the unauthorized reader");
    std::cout << "[Test] unauthorized reader pid=" << pid
              << " (vol=" << vol << " frn=" << frn << ")\n";

    bool suspended = false;
    for (int i = 0; i < 80; ++i) {
        if (IsThreadSuspended(tid)) { suspended = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(suspended, "the unauthorized reader was suspended by the file guard");
    CHECK(!FileExists(g_sentinel1),
          "the reader was suspended before completing its read (0 bytes: sentinel absent)");
    std::cout << "[Test] unauthorized reader pid " << pid
              << " suspended with 0 bytes read\n";

    // Capture its identity while it is parked (for the reuse-safe resume).
    uint64_t seq = 0, ct = 0;
    std::string reader_signer;
    CHECK(ResolveActor(pid, &seq, &ct, &reader_signer), "resolved the parked reader's identity");
    // cmd.exe is catalog-signed as "Microsoft Windows" - the guard's own
    // synchronous check resolves it even when the async registry signer is
    // still pending.
    const char* kReaderSigner = "Microsoft Windows";

    // We only paused it: resuming lets the (still unauthorized) read finish.
    CHECK(resume_process_windows(pid, seq, ct), "resume_process_windows");
    bool finished = false;
    for (int i = 0; i < 50; ++i) {
        if (FileExists(g_sentinel1)) { finished = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(finished, "after resume the reader completed its read (pause, not kill)");

    TerminateProcess(g_proc, 0);
    CloseHandle(g_proc);
    g_proc = nullptr;

    // ── authorized reader: not held ───────────────────────────────────────
    CHECK(add_resource_owner_signer_windows(vol, frn, kReaderSigner),
          "allowlisted the reader's signer");

    DWORD pid2 = 0, tid2 = 0;
    const auto t_start = std::chrono::steady_clock::now();
    HANDLE p2 = SpawnReader(g_protected, g_sentinel2, &pid2, &tid2);
    CHECK(p2 != nullptr, "spawned the authorized reader");

    bool ok2 = false;
    for (int i = 0; i < 100; ++i) {
        if (FileExists(g_sentinel2)) { ok2 = true; break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t_start).count();
    TerminateProcess(p2, 0);
    CloseHandle(p2);
    CHECK(ok2, "the authorized reader completed its read");
    CHECK(!IsThreadSuspended(tid2), "the authorized reader was never suspended");
    // Command includes a leading `ping -n 2` (~2 s) before the read, so the
    // measured figure is dominated by that; the guard's own overhead is the
    // remainder. The point of the bound is "not blocked indefinitely".
    std::cout << "[Test] authorized reader completed in " << elapsed_ms << " ms\n";
    CHECK(elapsed_ms < 8000, "authorized read was not held beyond a small bound");

    // ── disarm + remove ──────────────────────────────────────────────────
    CHECK(remove_file_guard_windows(narrow_path.c_str()), "remove_file_guard_windows");
    CHECK(set_response_enforcement_windows(0), "disarmed response enforcement");

    cleanup();
    std::cout << "\n>>> TEST SUCCESSFUL! Oplock synchronous hold validated. <<<"
              << std::endl;
    return 0;
}
