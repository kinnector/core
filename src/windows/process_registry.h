#pragma once

// WS1 (MVP_REACTIVE_PLAN.md) - the actor-identity spine.
//
// Every ETW event carries only a raw PID (TelemetryHeader.pid). Windows reuses
// PIDs aggressively, so a bare PID is not a safe key for "is the process that
// touched this protected resource the authorized owner?" - by the time the
// event is evaluated, that PID may belong to a different process entirely.
//
// ProcessRegistry maintains a live pid -> (sequence number, creation time,
// image path, Authenticode signer) map, fed from the Microsoft-Windows-
// Kernel-Process ProcessStart/ProcessStop events the ETW consumer already
// subscribes to, plus a one-time enumeration of processes that were already
// running when the engine started. It lets:
//   - etw_consumer.cpp stamp TelemetryHeader.actor_sequence_number on every
//     emitted event (reuse-resistant identity for the consumer to key on),
//   - the resolve_actor_windows / evaluate_access_windows / *_process_windows
//     FFI (WS4/WS5) resolve a live PID to its full identity + signer.
//
// No driver, no PPL: ProcessStart/Stop come from an ordinary elevated ETW
// session, and the enumeration uses Toolhelp + QueryFullProcessImageNameW.
// The handful of PPL-protected processes that can't be opened during the
// enumeration are recorded with whatever is available (image base name,
// sequence/creation-time possibly 0) - a credential stealer is never one of
// them, and processes that start *after* the engine is up always get a real
// sequence number straight from ETW.

#include <cstdint>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace kinnector::windows {

class ProcessRegistry {
public:
    enum class SignerState : uint8_t { Pending = 0, Signed = 1, Unsigned = 2 };

    struct ActorInfo {
        uint64_t sequence_number = 0;   // Kernel-Process ProcessSequenceNumber;
                                        // 0 == unavailable (pre-existing process
                                        // or older OS), never a real value.
        uint64_t create_time = 0;       // process creation time, FILETIME as
                                        // uint64; 0 only if it could not be read
                                        // (PPL-protected pre-existing process).
        std::wstring image_path;        // full path where resolvable, else the
                                        // base name, else empty.
        std::string signer_subject;     // leaf Authenticode signer display name;
                                        // empty unless signer_state == Signed.
        SignerState signer_state = SignerState::Pending;
    };

    ProcessRegistry();
    ~ProcessRegistry();

    // Start the signer-verification worker and enumerate already-running
    // processes. Idempotent-safe to call once per engine start.
    void Start();
    // Stop the worker thread. Safe to call if Start() was never called.
    void Stop();

    // Fed from etw_consumer.cpp's Kernel-Process handling.
    void OnProcessStart(uint32_t pid, uint64_t sequence_number,
                        uint64_t create_time, const std::wstring& image_path);
    void OnProcessStop(uint32_t pid);

    // WS6: schedule an off-hot-path Authenticode verification of `image_path`
    // so a later PeekSignerCache hit is served from cache. Used by the ETW
    // ImageLoad handler, which must not verify inline. Not tied to any process.
    void WarmSignerCache(const std::wstring& image_path);

    // Reuse-safe lookup. Returns false if the PID is not currently tracked.
    bool Lookup(uint32_t pid, ActorInfo* out) const;

    // Convenience for the hot path: just the sequence number (0 if untracked).
    uint64_t SequenceNumberFor(uint32_t pid) const;

    size_t Count() const;

private:
    void EnumerateExistingProcesses();
    void WorkerLoop();
    void EnqueueForVerification(uint32_t pid, const std::wstring& image_path);

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, ActorInfo> by_pid_;

    // Signer verification is deduplicated process-wide via
    // authenticode.h's CachedVerifyAuthenticodeSignature (shared with the
    // ETW ImageLoad path), so there is no per-instance signature cache here.

    // Verification work. Real per-process verifications (real_queue_) are
    // always drained before the ImageLoad warm-cache backfill (warm_queue_),
    // so a warm-cache flood can't starve identity resolution for a live
    // process. Warm queue is capped.
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<std::pair<uint32_t, std::wstring>> real_queue_;
    std::deque<std::wstring> warm_queue_;
    std::thread worker_;
    bool worker_running_ = false;
    static constexpr size_t kWarmQueueCap = 512;
};

} // namespace kinnector::windows
