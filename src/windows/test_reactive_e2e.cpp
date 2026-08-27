// WS4 + WS5 (MVP_REACTIVE_PLAN.md) - end-to-end reactive path.
//
// Registers a protected file + an owner-signer allowlist, has an unauthorized
// process touch it, and drives the full decision + response chain through the
// public FFI:
//   resolve_actor_windows -> evaluate_access_windows -> suspend/resume/
//   terminate_process_windows, including the reuse-safety guard.
//
// The "unauthorized process" is just cmd.exe reading a dummy file (cmd is
// Microsoft-signed; the allowlist is set to a different vendor). Nothing here
// reads a real credential store, decrypts anything, or exfiltrates.

#include "kinnector/ffi.h"

#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>

#define CHECK(cond, msg)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" \
                      << std::endl;                                            \
            cleanup();                                                          \
            return 1;                                                          \
        }                                                                      \
    } while (0)

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
std::wstring g_protected, g_unprotected;

void cleanup() {
    if (g_proc) { TerminateProcess(g_proc, 0); CloseHandle(g_proc); g_proc = nullptr; }
    if (!g_protected.empty()) DeleteFileW(g_protected.c_str());
    if (!g_unprotected.empty()) DeleteFileW(g_unprotected.c_str());
    stop_telemetry_engine();
}

// Spawn "cmd /c type <file> & ping -n N" - reads the file, then stays alive.
HANDLE SpawnReader(const std::wstring& file, DWORD* out_pid, DWORD* out_tid) {
    std::wstring cl = L"cmd.exe /c \"type \"" + file + L"\" >nul & ping -n 40 127.0.0.1 >nul\"";
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

// Definitive check that our process-suspend took: SuspendThread returns the
// PREVIOUS suspend count; >= 1 means the process was already suspended.
bool IsThreadSuspended(DWORD tid) {
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) return false;
    DWORD prev = SuspendThread(th);
    if (prev != (DWORD)-1) ResumeThread(th);  // undo our probe
    CloseHandle(th);
    return prev != (DWORD)-1 && prev >= 1;
}

// Same (volume serial, file reference number) pair core keys protected
// resources on - resolved here directly rather than pulling in the C++ header,
// so this test can link only the shared library (for the FFI).
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

constexpr int kSkip = 127;

} // namespace

int main() {
    std::cout << "=== Running Windows Reactive E2E (WS4+WS5) Test ===" << std::endl;
    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not elevated." << std::endl;
        return kSkip;
    }

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const auto pid_s = std::to_wstring(GetCurrentProcessId());
    g_protected = std::wstring(tmp) + L"kinnector_e2e_protected_" + pid_s + L".dat";
    g_unprotected = std::wstring(tmp) + L"kinnector_e2e_plain_" + pid_s + L".dat";
    { std::ofstream f(g_protected, std::ios::binary); f << "dummy protected content"; }
    { std::ofstream f(g_unprotected, std::ios::binary); f << "nothing special"; }

    if (!initialize_telemetry_engine(nullptr, "\\\\.\\pipe\\kinnector-e2e-test", "tok")) {
        std::cerr << "[Test] initialize_telemetry_engine failed (elevation?)" << std::endl;
        cleanup();
        return 1;
    }
    set_telemetry_profile_windows(1);  // reactive: the MVP's real profile
    if (!start_telemetry_engine()) {
        std::cerr << "[Test] start_telemetry_engine failed" << std::endl;
        cleanup();
        return 1;
    }

    uint32_t vol = 0;
    uint64_t frn = 0;
    CHECK(ResolveFileId(g_protected, &vol, &frn), "resolved the protected file's (vol, frn)");

    // The agent registers the file and an owner allowlist that does NOT include
    // Microsoft (so cmd.exe is unauthorized).
    CHECK(add_protected_resource_windows(vol, frn, 1), "add_protected_resource_windows");
    CHECK(add_resource_owner_signer_windows(vol, frn, "Some Unrelated Vendor LLC"),
          "add_resource_owner_signer_windows");
    {
        char np[512];
        WideCharToMultiByte(CP_UTF8, 0, g_protected.c_str(), -1, np, sizeof(np), nullptr, nullptr);
        add_telemetry_path_filter_windows(np);  // exercise the emit-path filter
    }

    // ── unauthorized actor touches the protected file ──────────────────────
    DWORD pid = 0, tid = 0;
    g_proc = SpawnReader(g_protected, &pid, &tid);
    CHECK(g_proc != nullptr, "spawned the reader process");

    uint64_t seq = 0, ct = 0;
    std::string signer;
    bool resolved = false;
    for (int i = 0; i < 60 && !resolved; ++i) {
        if (ResolveActor(pid, &seq, &ct, &signer) && !signer.empty()) resolved = true;
        else std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    CHECK(resolved, "resolve_actor_windows resolved the reader (pid, seq, ct, signer)");
    std::cout << "[Test] actor seq=" << seq << " ct=" << ct << " signer='" << signer << "'\n";
    CHECK(seq != 0 || ct != 0, "at least one reuse-safe identity field is populated");

    uint32_t verdict = 999;
    char reason[128] = {};
    char narrow_protected[512];
    WideCharToMultiByte(CP_UTF8, 0, g_protected.c_str(), -1, narrow_protected,
                        sizeof(narrow_protected), nullptr, nullptr);
    CHECK(evaluate_access_windows(pid, 1, narrow_protected, &verdict, reason, sizeof(reason)),
          "evaluate_access_windows returned a verdict");
    std::cout << "[Test] verdict=" << verdict << " reason='" << reason << "'\n";
    CHECK(verdict == 2, "verdict is UNAUTHORIZED (2) - signed actor, signer not in allowlist");

    // NOT_PROTECTED control.
    char narrow_plain[512];
    WideCharToMultiByte(CP_UTF8, 0, g_unprotected.c_str(), -1, narrow_plain,
                        sizeof(narrow_plain), nullptr, nullptr);
    uint32_t v2 = 999;
    evaluate_access_windows(pid, 1, narrow_plain, &v2, nullptr, 0);
    CHECK(v2 == 0, "an unprotected file evaluates to NOT_PROTECTED (0)");

    // ── response: reuse guard, then suspend / resume / terminate ───────────
    CHECK(set_response_enforcement_windows(1), "armed response enforcement");

    CHECK(!suspend_process_windows(pid, seq ? seq + 777777 : 0, ct ? ct + 5 : 0),
          "suspend REFUSED when the expected identity does not match (PID-reuse guard)");
    CHECK(!IsThreadSuspended(tid), "the process was NOT suspended by the refused call");

    CHECK(suspend_process_windows(pid, seq, ct), "suspend_process_windows succeeded");
    CHECK(IsThreadSuspended(tid), "the target process is actually suspended");

    CHECK(resume_process_windows(pid, seq, ct), "resume_process_windows succeeded");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(!IsThreadSuspended(tid), "the target process is running again after resume");

    CHECK(terminate_process_windows(pid, seq, ct), "terminate_process_windows succeeded");
    CHECK(WaitForSingleObject(g_proc, 5000) == WAIT_OBJECT_0, "target process actually exited");
    DWORD ec = STILL_ACTIVE;
    GetExitCodeProcess(g_proc, &ec);
    CHECK(ec != STILL_ACTIVE, "target process is gone");
    CloseHandle(g_proc);
    g_proc = nullptr;

    // Disarm and confirm it no-ops.
    CHECK(set_response_enforcement_windows(0), "disarmed response enforcement");
    CHECK(!terminate_process_windows(GetCurrentProcessId(), 1, 1),
          "response primitives no-op while disarmed (and never target self anyway)");

    // ── authorized path ───────────────────────────────────────────────────
    CHECK(add_resource_owner_signer_windows(vol, frn, signer.c_str()),
          "added the actor's real signer to the allowlist");
    DWORD pid2 = 0, tid2 = 0;
    HANDLE p2 = SpawnReader(g_protected, &pid2, &tid2);
    CHECK(p2 != nullptr, "spawned a second reader");
    uint64_t s2 = 0, c2 = 0; std::string sg2;
    bool r2 = false;
    for (int i = 0; i < 60 && !r2; ++i) {
        if (ResolveActor(pid2, &s2, &c2, &sg2) && !sg2.empty()) r2 = true;
        else std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    uint32_t v3 = 999;
    char reason3[128] = {};
    bool got3 = r2 && evaluate_access_windows(pid2, 1, narrow_protected, &v3, reason3, sizeof(reason3));
    TerminateProcess(p2, 0);
    CloseHandle(p2);
    CHECK(got3, "evaluate_access_windows for the second reader");
    std::cout << "[Test] authorized-path verdict=" << v3 << " reason='" << reason3 << "'\n";
    CHECK(v3 == 1, "verdict is AUTHORIZED (1) once the actor's signer is allowlisted");

    cleanup();
    std::cout << "\n>>> TEST SUCCESSFUL! Reactive decision + response chain validated. <<<"
              << std::endl;
    return 0;
}
