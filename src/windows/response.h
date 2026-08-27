#pragma once

// WS5 (MVP_REACTIVE_PLAN.md) - reactive response primitives.
//
// No driver: these are ordinary usermode OpenProcess + NtSuspendProcess /
// TerminateProcess calls. They are dumb executors - the agent decides WHAT to
// act on (via evaluate_access_windows); this just carries it out, with one
// safety property: every call re-resolves the PID against ProcessRegistry and
// REFUSES if the live identity does not match what the caller expected, so a
// reused PID is never suspended/killed by mistake.
//
// Disarmed by default. set_enforcement_enabled(true) must be called explicitly
// (core/CLAUDE.md: "any function that can arm blocking must default to off").
//
// Honest limits: best-effort and racy (a fast single read can complete before
// the suspend lands - that is what the WS7 oplock hold is for); cannot touch a
// PPL-protected target (infostealers are never PPL); a fully-privileged
// kernel/BYOVD attacker is out of scope.

#include <atomic>
#include <cstdint>

namespace kinnector::windows {

class ProcessRegistry;

class ResponseEngine {
public:
    void SetEnforcementEnabled(bool enabled) { enabled_.store(enabled); }
    bool EnforcementEnabled() const { return enabled_.load(); }

    // Each returns true only if the identity guard passed AND the OS call
    // succeeded. `expected_sequence_number` / `expected_create_time`: pass what
    // the triggering event reported (0 for "unknown"); the guard passes when
    // either a non-zero sequence number matches or a non-zero creation time
    // matches. Both zero -> refuse (cannot verify identity).
    bool Suspend(uint32_t pid, uint64_t expected_sequence_number,
                 uint64_t expected_create_time, ProcessRegistry* reg);
    bool Resume(uint32_t pid, uint64_t expected_sequence_number,
                uint64_t expected_create_time, ProcessRegistry* reg);
    bool Terminate(uint32_t pid, uint64_t expected_sequence_number,
                   uint64_t expected_create_time, ProcessRegistry* reg);

private:
    enum class Action { Suspend, Resume, Terminate };
    bool Act(Action action, uint32_t pid, uint64_t expected_seq,
             uint64_t expected_ct, ProcessRegistry* reg);

    std::atomic<bool> enabled_{false};
};

} // namespace kinnector::windows
