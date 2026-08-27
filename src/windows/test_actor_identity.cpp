// WS1 (MVP_REACTIVE_PLAN.md) - ProcessRegistry / actor-identity spine.
//
// Proves, against the real Kernel-Process ETW stream (no driver, no PPL):
//   1. a spawned process is tracked with a real, non-zero sequence number,
//   2. non-ProcessCreate events carry that same sequence number in
//      TelemetryHeader.actor_sequence_number,
//   3. when a tracked process exits, its identity is PRUNED - so a later
//      process that reuses the PID can never inherit the dead one's identity
//      (the direct anti-misattribution guarantee),
//   4. if the same PID is observed reused, the new instance gets a DIFFERENT
//      sequence number,
//   5. the async Authenticode-signer worker actually resolves signers for
//      real running processes.
//
// Nothing here reads credentials, injects, spoofs a PID, or does anything a
// stealer would - it spawns `cmd /c` no-ops and reads its own test file.

#include "etw_consumer.h"
#include <windows.h>
#include <tlhelp32.h>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using kinnector::windows::EtwConsumer;
using kinnector::windows::ProcessRegistry;

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::vector<TelemetryEvent> g_events;

void OnEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.push_back(event);
    g_cv.notify_all();
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

// Wait until predicate(collected events) is satisfied.
template <typename Pred>
bool WaitFor(Pred pred, int timeout_ms) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                         [&] { return pred(g_events); });
}

bool WaitForProcessCreate(DWORD child_pid, TelemetryEvent* out, int timeout_ms) {
    return WaitFor(
        [&](const std::vector<TelemetryEvent>& evs) {
            for (const auto& ev : evs) {
                if (ev.header.event_type == EventType::ProcessCreate &&
                    ev.details.process_create.child_pid == child_pid) {
                    *out = ev;
                    return true;
                }
            }
            return false;
        },
        timeout_ms);
}

// Search only events at index >= from_idx - needed once a PID has been reused,
// since g_events keeps the earlier process's ProcessCreate too.
bool WaitForProcessCreateFrom(DWORD child_pid, size_t from_idx, TelemetryEvent* out,
                              int timeout_ms) {
    return WaitFor(
        [&](const std::vector<TelemetryEvent>& evs) {
            for (size_t i = from_idx; i < evs.size(); ++i) {
                if (evs[i].header.event_type == EventType::ProcessCreate &&
                    evs[i].details.process_create.child_pid == child_pid) {
                    *out = evs[i];
                    return true;
                }
            }
            return false;
        },
        timeout_ms);
}

size_t EventCount() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_events.size();
}

bool WaitForProcessStop(DWORD pid, int timeout_ms) {
    return WaitFor(
        [&](const std::vector<TelemetryEvent>& evs) {
            for (const auto& ev : evs) {
                if (ev.header.event_type == EventType::ProcessStop &&
                    ev.header.pid == pid) {
                    return true;
                }
            }
            return false;
        },
        timeout_ms);
}

DWORD SpawnNoop() {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t cmdline[] = L"cmd.exe /c ver >nul";
    if (!CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pi.dwProcessId;
}

DWORD FindRunningPidByName(const wchar_t* exe_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

} // namespace

#define CHECK(cond, msg)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" \
                      << std::endl;                                            \
            consumer.Stop();                                                    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows Actor Identity (WS1) Test ===" << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not elevated - real Kernel-Process ETW "
                     "tracing requires Administrator." << std::endl;
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
    ProcessRegistry* reg = consumer.GetProcessRegistry();

    // ── 1 & 2: tracked identity + header stamping ────────────────────────────
    std::cout << "[Test] Spawning a child that reads a file..." << std::endl;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Reads a file (→ a non-ProcessCreate event attributed to this child) then
    // stays alive a few seconds so the async worker resolves it while tracked.
    wchar_t cmdline[] =
        L"cmd.exe /c \"type C:\\Windows\\System32\\drivers\\etc\\hosts >nul & "
        L"ping -n 5 127.0.0.1 >nul\"";
    CHECK(CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                         nullptr, nullptr, &si, &pi),
          "CreateProcess file-reading child");
    DWORD reader_pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    TelemetryEvent pc{};
    if (!WaitForProcessCreate(reader_pid, &pc, 15000)) {
        std::cerr << "[Test] Timed out waiting for ProcessCreate for pid " << reader_pid << std::endl;
        consumer.Stop();
        return 1;
    }
    uint64_t reader_seq = pc.details.process_create.child_sequence_number;
    CHECK(reader_seq != 0, "child_sequence_number is non-zero on this OS build");

    ProcessRegistry::ActorInfo ai{};
    CHECK(reg->Lookup(reader_pid, &ai), "spawned child is tracked in ProcessRegistry");
    CHECK(ai.sequence_number == reader_seq,
          "registry's sequence number matches the ProcessCreate event's");
    std::wcout << L"[Test] tracked image_path=" << ai.image_path << std::endl;

    // The worker normalizes the ETW device path (\Device\HarddiskVolumeN\...)
    // to a Win32 drive path so it can be signer-verified.
    bool normalized = false;
    for (int i = 0; i < 40 && !normalized; ++i) {
        ProcessRegistry::ActorInfo cur{};
        if (reg->Lookup(reader_pid, &cur) && cur.image_path.size() > 2 &&
            cur.image_path[1] == L':' && cur.image_path[2] == L'\\') {
            normalized = true;
            std::wcout << L"[Test] normalized image_path=" << cur.image_path << std::endl;
        }
        if (!normalized) std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    CHECK(normalized, "ETW device-path image name is normalized to a Win32 path");

    bool saw_stamped_event = WaitFor(
        [&](const std::vector<TelemetryEvent>& evs) {
            for (const auto& ev : evs) {
                if (ev.header.pid == reader_pid &&
                    ev.header.event_type != EventType::ProcessCreate) {
                    if (ev.header.actor_sequence_number == reader_seq) return true;
                }
            }
            return false;
        },
        15000);
    CHECK(saw_stamped_event,
          "a non-ProcessCreate event for the child carried actor_sequence_number "
          "== its real sequence number");

    // ── 3: prune on exit ────────────────────────────────────────────────────
    std::cout << "[Test] Spawning a child, confirming it is tracked while alive, "
                 "then that its identity is pruned once it exits..." << std::endl;
    STARTUPINFOW si3{};
    si3.cb = sizeof(si3);
    PROCESS_INFORMATION pi3{};
    wchar_t cmd3[] = L"cmd.exe /c ping -n 20 127.0.0.1 >nul";  // ~19s, we kill it early
    CHECK(CreateProcessW(nullptr, cmd3, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                         nullptr, nullptr, &si3, &pi3),
          "spawned a live child");
    DWORD ephemeral_pid = pi3.dwProcessId;
    CloseHandle(pi3.hThread);

    TelemetryEvent ep_pc{};
    if (!WaitForProcessCreate(ephemeral_pid, &ep_pc, 15000)) {
        std::cerr << "[Test] no ProcessCreate for the live child" << std::endl;
        TerminateProcess(pi3.hProcess, 0); CloseHandle(pi3.hProcess);
        consumer.Stop();
        return 1;
    }
    uint64_t ephemeral_seq = ep_pc.details.process_create.child_sequence_number;

    bool tracked_alive = false;
    for (int i = 0; i < 40 && !tracked_alive; ++i) {
        if (reg->Lookup(ephemeral_pid, nullptr)) tracked_alive = true;
        else std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!tracked_alive) {
        std::cerr << "[Test] live child never appeared in the registry" << std::endl;
        TerminateProcess(pi3.hProcess, 0); CloseHandle(pi3.hProcess);
        consumer.Stop();
        return 1;
    }

    TerminateProcess(pi3.hProcess, 0);
    WaitForSingleObject(pi3.hProcess, 5000);
    CloseHandle(pi3.hProcess);

    CHECK(WaitForProcessStop(ephemeral_pid, 15000), "ProcessStop observed for the child");
    bool pruned = false;
    for (int i = 0; i < 40 && !pruned; ++i) {
        if (!reg->Lookup(ephemeral_pid, nullptr)) pruned = true;
        else std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(pruned,
          "the child's identity is PRUNED after exit - a PID-reusing "
          "process cannot inherit it");

    // ── 4: reused PID gets a different sequence number ──────────────────────
    std::cout << "[Test] Looking for a natural PID reuse of " << ephemeral_pid
              << " (best-effort)..." << std::endl;
    bool observed_reuse = false;
    for (int i = 0; i < 120 && !observed_reuse; ++i) {
        size_t before = EventCount();
        DWORD p = SpawnNoop();
        if (p != ephemeral_pid) continue;
        TelemetryEvent r_pc{};
        if (!WaitForProcessCreateFrom(p, before, &r_pc, 8000)) break;
        uint64_t reused_seq = r_pc.details.process_create.child_sequence_number;
        CHECK(reused_seq != ephemeral_seq,
              "a process reusing the PID gets a DIFFERENT sequence number");
        std::cout << "[Test] PID " << p << " reused: old seq=" << ephemeral_seq
                  << " new seq=" << reused_seq << std::endl;
        observed_reuse = true;
    }
    if (!observed_reuse) {
        std::cout << "[Test] NOTE: no natural PID reuse observed in the budget - "
                     "the prune check above already covers the core guarantee."
                  << std::endl;
    }

    // ── 5: async signer verification actually runs ─────────────────────────
    std::cout << "[Test] Waiting for the signer-verification worker to resolve "
                 "signers of real running processes..." << std::endl;
    bool any_signed = false;
    for (int i = 0; i < 40 && !any_signed; ++i) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    ProcessRegistry::ActorInfo info{};
                    if (reg->Lookup(pe.th32ProcessID, &info) &&
                        info.signer_state == ProcessRegistry::SignerState::Signed &&
                        !info.signer_subject.empty()) {
                        std::cout << "[Test] verified signer: " << info.signer_subject
                                  << std::endl;
                        any_signed = true;
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        if (!any_signed) std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    CHECK(any_signed,
          "the async worker resolved at least one real process to a signed "
          "Authenticode identity");

    // Targeted: explorer.exe is embedded-signed (see test_resource_identity.cpp).
    DWORD explorer_pid = FindRunningPidByName(L"explorer.exe");
    if (explorer_pid != 0) {
        bool explorer_signed = false;
        for (int i = 0; i < 40 && !explorer_signed; ++i) {
            ProcessRegistry::ActorInfo info{};
            if (reg->Lookup(explorer_pid, &info) &&
                info.signer_state == ProcessRegistry::SignerState::Signed) {
                explorer_signed = true;
            }
            if (!explorer_signed) std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        CHECK(explorer_signed, "running explorer.exe resolves as signed");
    } else {
        std::cout << "[Test] NOTE: no explorer.exe running - skipped the targeted "
                     "embedded-signature check (general check above still passed)."
                  << std::endl;
    }

    consumer.Stop();
    std::cout << "\n>>> TEST SUCCESSFUL! Actor-identity spine validated. <<<" << std::endl;
    return 0;
}
