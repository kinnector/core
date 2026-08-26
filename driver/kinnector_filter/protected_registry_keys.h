#pragma once

// Kernel-safe protected-registry-key store for Phase 7 step 3b
// (WINDOWS_COVERAGE_PLAN.md). Same fixed-capacity, spinlock-guarded design
// as protected_resources.h (no STL, no dynamic allocation on the hot path),
// but keyed on a registry key's NT-native object path (e.g.
// "\REGISTRY\MACHINE\SOFTWARE\...", NOT the Win32 "HKLM\..." form) instead
// of a volume-serial+FRN pair - registry keys don't have a canonical
// identity scheme analogous to a file's, so the resolved object name *is*
// the identity here. Confirmed empirically via NtQueryObject(ObjectName
// Information) on a real key handle from user mode before writing this -
// don't re-derive the path format from documentation alone if extending
// this further, verify against a real handle the same way.
//
// Real config wiring is NOT part of this step, same scope note as
// protected_resources.h - entries are only ever seeded for controlled local
// testing.

#include <ntddk.h>

#define KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS 64
#define KINNECTOR_REGISTRY_KEY_PATH_MAX_CHARS 512

VOID
KinnectorProtectedRegistryKeysInit(
    VOID
    );

// Returns FALSE if the table is full, or if KeyPath is too long to fit -
// either way, the caller never treats a failed add as a reason to deny
// anything; an unprotectable key just stays unprotected.
BOOLEAN
KinnectorAddProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    );

BOOLEAN
KinnectorRemoveProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    );

// Case-insensitive exact match against KeyPath (the registry namespace is
// case-insensitive) - no prefix/subtree matching in this step.
BOOLEAN
KinnectorIsProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    );

VOID
KinnectorProtectedRegistryKeysClear(
    VOID
    );
