#pragma once

// Kernel-safe reimplementation of core/src/windows/resource_identity.h's
// ProtectedResourceStore, for Phase 7 step 2 (WINDOWS_COVERAGE_PLAN.md).
// User-mode STL (std::mutex/unordered_map) can't cross into kernel context,
// so this is a fixed-capacity array guarded by a spin lock instead - no
// dynamic allocation on the hot path (every file create on an attached
// volume calls KinnectorIsProtectedResource).
//
// Real config wiring (usermode agent -> driver, most likely via
// FltCreateCommunicationPort) is NOT part of this step - see the scope note
// in kinnector_filter.c's KinnectorPostCreate. For now entries are only
// seeded for local, controlled testing (e.g. via WinDbg or a temporary
// debug-only call), never from any hardcoded path baked into DriverEntry -
// a typo there could accidentally protect (and deny access to) something
// system-critical the moment the driver loads.

#include <ntddk.h>

#define KINNECTOR_MAX_PROTECTED_RESOURCES 256

typedef struct _KINNECTOR_RESOURCE_KEY {
    ULONG VolumeSerialNumber;
    LARGE_INTEGER FileReferenceNumber;
} KINNECTOR_RESOURCE_KEY;

VOID
KinnectorProtectedResourcesInit(
    VOID
    );

// Returns FALSE only if the table is full - callers never treat a failed
// add as a reason to deny access; an unprotectable resource just stays
// unprotected, it never fails open into "deny everything."
BOOLEAN
KinnectorAddProtectedResource(
    _In_ ULONG VolumeSerialNumber,
    _In_ LARGE_INTEGER FileReferenceNumber
    );

BOOLEAN
KinnectorRemoveProtectedResource(
    _In_ ULONG VolumeSerialNumber,
    _In_ LARGE_INTEGER FileReferenceNumber
    );

BOOLEAN
KinnectorIsProtectedResource(
    _In_ ULONG VolumeSerialNumber,
    _In_ LARGE_INTEGER FileReferenceNumber
    );

VOID
KinnectorProtectedResourcesClear(
    VOID
    );
