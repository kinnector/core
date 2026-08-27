#include "response.h"
#include "process_registry.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

namespace kinnector::windows {

namespace {

using NtProcFn = LONG(NTAPI*)(HANDLE);

NtProcFn ResolveNt(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<NtProcFn>(
                       reinterpret_cast<void*>(GetProcAddress(ntdll, name)))
                 : nullptr;
}

// Fallback when NtSuspend/ResumeProcess is unavailable: walk the target's
// threads.
bool ForEachThreadDo(uint32_t pid, bool suspend) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    bool acted = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!th) continue;
            if (suspend) { if (SuspendThread(th) != (DWORD)-1) acted = true; }
            else         { if (ResumeThread(th)  != (DWORD)-1) acted = true; }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return acted;
}

} // namespace

bool ResponseEngine::Act(Action action, uint32_t pid, uint64_t expected_seq,
                         uint64_t expected_ct, ProcessRegistry* reg) {
    if (!enabled_.load()) return false;
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return false;
    if (!reg) return false;

    ProcessRegistry::ActorInfo ai;
    const bool tracked = reg->Lookup(pid, &ai);

    const bool seq_ok = tracked && expected_seq != 0 && ai.sequence_number != 0 &&
                        ai.sequence_number == expected_seq;
    bool ct_ok = tracked && expected_ct != 0 && ai.create_time != 0 &&
                 ai.create_time == expected_ct;

    // Synchronous creation-time recheck. Needed because (a) under heavy ETW
    // load the Kernel-Process ProcessStart event lags seconds behind, so a
    // just-spawned WS7 opener is not in the registry yet, and (b) the
    // registry's create_time is ETW-timestamp-derived and does not equal
    // GetProcessTimes' value, so a caller that resolved expected_ct
    // synchronously (WS7) would never match the registry copy. Either way,
    // matching the LIVE creation time against expected_ct is reuse-safe.
    if (!seq_ok && !ct_ok && expected_ct != 0) {
        HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (q) {
            FILETIME cr{}, ex{}, kt{}, ut{};
            if (GetProcessTimes(q, &cr, &ex, &kt, &ut)) {
                const uint64_t live_ct =
                    (static_cast<uint64_t>(cr.dwHighDateTime) << 32) | cr.dwLowDateTime;
                if (live_ct == expected_ct) ct_ok = true;
            }
            CloseHandle(q);
        }
    }

    if (!seq_ok && !ct_ok) {
        std::cerr << "[response] identity mismatch for pid " << pid
                  << " - refusing (possible PID reuse)\n";
        return false;
    }

    if (action == Action::Terminate) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!h) return false;
        bool ok = TerminateProcess(h, 0xF12E) != 0;
        CloseHandle(h);
        return ok;
    }

    const bool suspend = (action == Action::Suspend);
    static NtProcFn nt_suspend = ResolveNt("NtSuspendProcess");
    static NtProcFn nt_resume = ResolveNt("NtResumeProcess");
    NtProcFn fn = suspend ? nt_suspend : nt_resume;

    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) return false;
    bool ok = false;
    if (fn) {
        ok = fn(h) >= 0;  // NTSTATUS >= 0 == success
    }
    CloseHandle(h);
    if (!ok) ok = ForEachThreadDo(pid, suspend);
    return ok;
}

bool ResponseEngine::Suspend(uint32_t pid, uint64_t seq, uint64_t ct, ProcessRegistry* reg) {
    return Act(Action::Suspend, pid, seq, ct, reg);
}
bool ResponseEngine::Resume(uint32_t pid, uint64_t seq, uint64_t ct, ProcessRegistry* reg) {
    return Act(Action::Resume, pid, seq, ct, reg);
}
bool ResponseEngine::Terminate(uint32_t pid, uint64_t seq, uint64_t ct, ProcessRegistry* reg) {
    return Act(Action::Terminate, pid, seq, ct, reg);
}

} // namespace kinnector::windows
