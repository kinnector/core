#pragma once

// Kernel-safe process-lineage table for Phase 7 step 4 (WINDOWS_COVERAGE_
// PLAN.md): "supersedes Phase 2's ETW-based interim mechanism as the
// authoritative source" for parent-child process identity. Keyed on
// (ProcessId, PsGetProcessCreateTimeQuadPart) on BOTH sides of the
// relationship - the same anti-PID-reuse composite key discipline
// core/src/windows/process_integrity.h and the Linux side of core already
// use. The "creator" side is resolved from PS_CREATE_NOTIFY_INFO's
// CreatingThreadId.UniqueProcess (the real, kernel-attributed calling
// process), never CreationInfo->ParentProcessId - that field is
// user-mode-supplied and trivially spoofable via
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. This is the whole reason step 4
// exists; see kinnector_filter.c's KinnectorProcessNotifyCallback for the
// empirical test that proves the distinction actually matters on this
// machine.
//
// Same fixed-capacity, lock-guarded design as protected_resources.h - no
// dynamic allocation on the hot path (every process create/exit calls into
// this). Unlike protected_registry_keys.h, a plain KSPIN_LOCK is correct
// and safe here: every comparison below is a pure HANDLE/LONGLONG integer
// compare, never a call into Rtl/Cm/Zw or anything that could touch paged
// memory - confirmed deliberately after the KSPIN_LOCK+RtlEqualUnicodeString
// crash documented in core_windows_phase7_step3b_crash_irql - don't add any
// string/Rtl/Cm/Zw call under this lock without re-checking that reasoning.
//
// Scope: this is the kernel's job only - delivering a trustworthy identity
// mapping. What to DO with that mapping (root-marking trusted binaries,
// propagating trust to children, policy decisions) stays in antitheftd's
// Rust side (heuristics.rs already owns exactly this for the Phase 2
// interim mechanism) per the established core/agent boundary - core never
// owns policy, only enforcement/identity. Nothing here is wired to any
// FFI/consumer yet; this step only proves the identity source itself.

#include <ntddk.h>

#define KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES 2048

VOID
KinnectorProcessLineageInit(
    VOID
    );

// Returns FALSE if the table is full - caller (the process-create callback)
// must never treat that as a reason to fail the process creation, only as
// "this one child's lineage won't be tracked." Idempotent: re-recording the
// same (ProcessId, CreateTime) overwrites the existing entry rather than
// erroring or duplicating.
BOOLEAN
KinnectorRecordProcessLineage(
    _In_ HANDLE ChildProcessId,
    _In_ LONGLONG ChildCreateTime,
    _In_ HANDLE CreatorProcessId,
    _In_ LONGLONG CreatorCreateTime
    );

// Called on process exit to bound table growth. Safe to call for an entry
// that was never recorded (full table, resolution failure at create time) -
// just returns FALSE.
BOOLEAN
KinnectorRemoveProcessLineage(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime
    );

BOOLEAN
KinnectorLookupProcessLineage(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime,
    _Out_ HANDLE* OutCreatorProcessId,
    _Out_ LONGLONG* OutCreatorCreateTime
    );

VOID
KinnectorProcessLineageClear(
    VOID
    );
