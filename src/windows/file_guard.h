#pragma once

// WS7 (MVP_REACTIVE_PLAN.md) - synchronous oplock hold for the flagship
// at-rest credential file set (SSH keys, wallet files, password-manager
// vaults).
//
// Tier A (WS5) can interrupt a multi-step stealer but cannot beat a single
// CreateFile + ReadFile + exit that finishes inside the ETW delivery budget
// (WS6 measured p50 ~95 ms, p95 ~150-200 ms; a one-file read is < 10 ms).
// For a small, high-value, rarely-opened set of files we want a real hold.
//
// Mechanism - 100% usermode, no driver, no PPL:
//   1. core opens one persistent handle to each guarded file and requests a
//      read+handle oplock (FSCTL_REQUEST_OPLOCK, OPLOCK_LEVEL_CACHE_READ |
//      OPLOCK_LEVEL_CACHE_HANDLE) - a documented Win7+ filesystem primitive.
//      Our handle is opened with FILE_READ_ATTRIBUTES only, which never
//      triggers a sharing violation, so it does not interfere with a
//      legitimate owner opening the file (even exclusively).
//   2. A foreign CreateFile on the file breaks the oplock; the OS holds that
//      open pending core's acknowledgement.
//   3. In that window core correlates the break to a pid (via the
//      Microsoft-Windows-Kernel-File FileCreate ETW event for the same
//      path), resolves the actor, and runs the exact same owner-set check
//      evaluate_access_windows uses. UNAUTHORIZED + enforcement armed ->
//      suspend the opener, THEN acknowledge. The opener resumes already
//      suspended and never reads.
//   4. Anything else - authorized, unknown actor, no correlation within the
//      budget, disarmed, any error - acknowledge immediately. FAIL OPEN on
//      every uncertainty; never hang legitimate access.
//
// Caveats (also in MVP_REACTIVE_PLAN.md WS7):
//   - Only works while core holds the file open. If a legitimate owner
//     already holds it open when AddGuard runs, the handle-level oplock
//     cannot be granted; the guard is retained and the worker retries.
//   - One handle per guarded file. Keep the guarded set tiny (< 50).
//   - Legitimate opens break the oplock too - the authorized path must stay
//     fast (it is: one store lookup + one signer-cache hit).
//   - There is a sub-millisecond window between acknowledging one break and
//     re-arming where a second opener is not held. Acceptable for the MVP
//     threat model (these files are opened seconds-to-days apart).

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <evntrace.h>
#include <evntcons.h>

namespace kinnector::windows {

class FileGuard {
public:
    // Called from the break-handler thread once a break has been correlated
    // to a pid. Return true iff the opener was found UNAUTHORIZED *and* was
    // actually suspended - the guard then acknowledges the break leaving it
    // suspended. Return false for every other outcome (authorized, unknown,
    // disarmed, any failure): the guard acknowledges without acting (fail
    // open). Must not block on anything the FFI teardown path holds - it runs
    // on the worker thread, which FileGuard::Stop() joins before teardown.
    enum class Verdict { FailOpen, Suspended, Authorized };
    struct EnforceResult {
        Verdict verdict = Verdict::FailOpen;
        uint32_t pid = 0;   // the opener that was suspended / authorized
    };

    // Given the candidate opener pids for one break (most-recent first) and the
    // guarded file's identity, evaluate each and return the outcome for the
    // first actionable one.
    using EnforceFn = std::function<EnforceResult(const std::vector<uint32_t>& candidate_pids,
                                                  uint32_t volume_serial,
                                                  uint64_t file_reference_number)>;

    explicit FileGuard(EnforceFn enforce);
    ~FileGuard();

    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;

    void Start();
    void Stop();

    // `path` is a Win32 path (UTF-16). Opens the file, resolves its canonical
    // identity + NT device path, and arms the oplock synchronously. Returns
    // false if the file cannot be opened; returns true even if the oplock
    // could not be granted right now (the worker keeps retrying).
    bool AddGuard(const std::wstring& path);
    bool RemoveGuard(const std::wstring& path);

    // Fed from the ETW Kernel-File FileCreate path (via the ffi event
    // callback). Cheap: records into a small ring and, only if a break is
    // currently being correlated, signals the worker.
    void NotifyFileCreate(const char* file_path_utf8, uint32_t pid);

    size_t Count() const;

private:
    struct Guard {
        std::wstring key;          // AddGuard's input path, upper-cased (identity within guards_)
        std::wstring open_path;    // AddGuard's input path, as given (for re-opening the handle)
        std::wstring device_path;  // \Device\HarddiskVolumeN\... upper-cased, for ETW correlation
        uint32_t volume_serial = 0;
        uint64_t frn = 0;
        HANDLE file = INVALID_HANDLE_VALUE;
        OVERLAPPED ov{};           // ov.hEvent is a manual-reset event
        REQUEST_OPLOCK_INPUT_BUFFER in{};
        REQUEST_OPLOCK_OUTPUT_BUFFER out{};
        bool armed = false;
        DWORD last_break_tick = 0;
        int fast_break_run = 0;         // consecutive near-instant re-breaks
        int uncorrelated_run = 0;       // consecutive breaks we could not correlate
        uint32_t vetted_pid = 0;        // last opener we already decided on
        DWORD vetted_tick = 0;
    };

    static bool Arm(Guard& g);          // issue the REQUEST ioctl on g (touches only g)
    static void CloseGuard(Guard& g);
    void WorkerLoop();
    void DrainPending();                // adopt pending_add_ / apply pending_remove_
    void HandleBreak(Guard& g);
    void Acknowledge(Guard& g);

    // A dedicated single-provider ETW session (Microsoft-Windows-Kernel-File,
    // CREATE keyword only) that feeds NotifyFileCreate. The main telemetry
    // consumer's FileCreate events lag seconds behind a saturated box; this
    // session carries ~1% of that volume and stays real-time, so oplock-break
    // correlation works under load. Best-effort: if it fails to start, the
    // guard still gets FileCreate events from the main consumer via the ffi
    // callback, just slower.
    bool StartCorrelationSession();
    void StopCorrelationSession();
    void FlushCorrelationSession();   // EVENT_TRACE_CONTROL_FLUSH - deliver buffered events now
    static void WINAPI CorrelationCallback(PEVENT_RECORD event);
    static DWORD WINAPI CorrelationTraceThread(LPVOID param);

    EnforceFn enforce_;

    mutable std::mutex mutex_;                            // guards_, pending_*
    std::vector<std::unique_ptr<Guard>> guards_;          // worker-owned after adoption
    std::vector<std::unique_ptr<Guard>> pending_add_;
    std::vector<std::wstring> pending_remove_;

    HANDLE shutdown_event_ = nullptr;                     // manual-reset
    HANDLE rebuild_event_ = nullptr;                      // auto-reset
    std::thread worker_;
    std::atomic<bool> running_{false};

    TRACEHANDLE corr_session_ = 0;
    TRACEHANDLE corr_trace_ = 0;
    HANDLE corr_thread_ = nullptr;
    static FileGuard* s_instance_;                        // for CorrelationCallback

    // Correlation handoff, all under corr_mutex_.
    struct RecentOpen {
        std::wstring path;
        uint32_t pid = 0;
        DWORD tick = 0;
    };
    std::mutex corr_mutex_;
    std::condition_variable corr_cv_;
    std::wstring corr_want_;                              // empty == no break in flight
    std::vector<uint32_t> corr_pids_;                     // candidate openers seen during the wait
    std::array<RecentOpen, 32> recent_{};
    size_t recent_idx_ = 0;

    // How long an unidentified foreign open of a guarded file is held before
    // we give up correlating and fail open. The dedicated correlation session
    // (Kernel-File CREATE only) normally delivers in tens of ms even under
    // load, so this is mostly a ceiling for the pathological case.
    static constexpr DWORD kCorrelationBudgetMs = 1400;
    static constexpr DWORD kVettedCorrelationMs = 300;  // shorter wait while a vetted opener is active
    static constexpr DWORD kCollectExtraMs = 150;   // keep collecting after the first hit
    static constexpr DWORD kVettedGraceMs = 4000;   // trust a just-decided opener this long
};

} // namespace kinnector::windows
