#pragma once

#include "resource_identity.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>

namespace kinnector::windows {

// Tracks whether a specific running process instance currently has an
// active injection indicator against it (VirtualAlloc/WriteProcessMemory/
// SetThreadContext/QueueUserAPC/remote-thread creation - antitheft.md §3's
// list), for the self-update trust decision: a vendor's updater script (or
// the binary updating itself) is trusted to write a protected resource
// if its own process instance is currently "clear," on top of the signer
// check in ProtectedResourceStore::IsAuthorizedModifyingPath.
//
// Composite-keyed on (pid, create_time), NEVER pid alone - same discipline
// as every lineage/identity table in antitheft.md §3/§4: Windows reuses
// PIDs aggressively, so a pid-only table lets a flag against a dead
// process get silently inherited by an unrelated new one holding the same
// pid. create_time is the process's own creation timestamp (e.g.
// GetProcessTimes' lpCreationTime, as a 64-bit FILETIME value) captured at
// the moment the caller identified the process, not re-derived later.
//
// IMPORTANT - this is currently a NO-OP pass-through, not a working
// injection defense: nothing in core calls FlagProcessInjected yet.
// Phase 4's ETW-TI injection detection (WINDOWS_COVERAGE_PLAN.md) - the
// only real source for these indicators - is blocked pending genuine
// Antimalware-PPL/ELAM certification (core_windows_phase4_etwti_blocked).
// IsProcessClear defaulting to true for every untracked process is a
// deliberate default-allow per the self-update design (trusted unless
// actively flagged), but until Phase 4 is unblocked and wired to call
// FlagProcessInjected, every process reads as "clear" unconditionally -
// don't present a true return here as proof any check actually happened.
class ProcessIntegrityStore {
public:
    bool FlagProcessInjected(uint32_t pid, uint64_t create_time);
    bool ClearProcessFlag(uint32_t pid, uint64_t create_time);
    bool IsProcessClear(uint32_t pid, uint64_t create_time) const;

private:
    struct Key {
        uint32_t pid;
        uint64_t create_time;
        bool operator==(const Key& other) const {
            return pid == other.pid && create_time == other.create_time;
        }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const {
            return std::hash<uint64_t>()((static_cast<uint64_t>(k.pid) << 32) ^ k.create_time);
        }
    };

    mutable std::mutex mutex_;
    std::unordered_set<Key, KeyHash> flagged_;
};

// The actual self-update authorization gate: BOTH signed by an allowlisted
// vendor (ProtectedResourceStore::IsAuthorizedModifyingPath) AND the
// modifying process instance is currently clear of injection indicators
// (ProcessIntegrityStore::IsProcessClear) - being signed is not sufficient
// on its own, a legitimately-signed updater binary can still be a hijacked
// process instance per antitheft.md §3's continuously-revocable-trust
// principle. Inherits ProcessIntegrityStore's current no-op caveat: until
// Phase 4's injection detection is wired up, the integrity half of this
// check always passes, so this reduces to the signer check alone for now.
bool IsAuthorizedSelfUpdate(const ProtectedResourceStore& resources,
                             const ProcessIntegrityStore& integrity,
                             uint32_t volume_serial, uint64_t file_reference_number,
                             const std::wstring& modifying_binary_path,
                             uint32_t modifying_pid, uint64_t modifying_process_create_time);

} // namespace kinnector::windows
