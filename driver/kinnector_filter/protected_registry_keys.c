#include "protected_registry_keys.h"

// SAFETY-CRITICAL, real bug hit and fixed 2026-08-26 - read before changing
// the synchronization primitive here. This store originally used a
// KSPIN_LOCK (KeAcquireInStackQueuedSpinLock), which raises IRQL to
// DISPATCH_LEVEL. RtlEqualUnicodeString - called on every lookup - turned
// out to execute from PAGED kernel code on this build
// (IP_IN_PAGED_CODE: nt!RtlEqualUnicodeString+0 in the resulting crash
// dump). Executing paged code at DISPATCH_LEVEL is fatal the instant that
// page isn't resident: this caused a real bugcheck 0xA
// (IRQL_NOT_LESS_OR_EQUAL), confirmed via kernel-dump analysis
// (MODULE_NAME: kinnector_filter, IMAGE_NAME: kinnector_filter.sys),
// triggered by a real registry read from WmiPrvSE.exe within seconds of
// loading. FAST_MUTEX is the fix: ExAcquireFastMutex only raises IRQL to
// APC_LEVEL (_IRQL_raises_(APC_LEVEL), confirmed against the WDK header
// before making this change, not assumed) - low enough that paged code and
// page faults are still serviced normally. Do not switch this back to a
// spinlock (or add a spinlock-guarded call to any other Rtl/Cm/Zw routine
// here) without first confirming, from the actual WDK header, that
// everything called while it's held is documented safe at DISPATCH_LEVEL -
// this bug is exactly what happens when that isn't checked.

typedef struct _KINNECTOR_PROTECTED_REGISTRY_ENTRY {
    WCHAR Buffer[KINNECTOR_REGISTRY_KEY_PATH_MAX_CHARS];
    UNICODE_STRING Path;
    BOOLEAN InUse;
} KINNECTOR_PROTECTED_REGISTRY_ENTRY;

static FAST_MUTEX gProtectedRegistryKeysMutex;
static KINNECTOR_PROTECTED_REGISTRY_ENTRY gProtectedRegistryKeys[KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS];

VOID
KinnectorProtectedRegistryKeysInit(
    VOID
    )
{
    ExInitializeFastMutex(&gProtectedRegistryKeysMutex);
    RtlZeroMemory(gProtectedRegistryKeys, sizeof(gProtectedRegistryKeys));
}

BOOLEAN
KinnectorAddProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    BOOLEAN added = FALSE;
    ULONG i;
    ULONG freeIndex = KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS;

    if (KeyPath == NULL || KeyPath->Length == 0 ||
        KeyPath->Length > (KINNECTOR_REGISTRY_KEY_PATH_MAX_CHARS - 1) * sizeof(WCHAR)) {
        return FALSE;
    }

    ExAcquireFastMutex(&gProtectedRegistryKeysMutex);

    // Idempotent: adding an already-protected key again is success, not a
    // duplicate entry.
    for (i = 0; i < KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS; i++) {
        if (gProtectedRegistryKeys[i].InUse &&
            RtlEqualUnicodeString(&gProtectedRegistryKeys[i].Path, KeyPath, TRUE)) {
            added = TRUE;
            goto Done;
        }
        if (freeIndex == KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS && !gProtectedRegistryKeys[i].InUse) {
            freeIndex = i;
        }
    }

    if (freeIndex < KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS) {
        KINNECTOR_PROTECTED_REGISTRY_ENTRY* entry = &gProtectedRegistryKeys[freeIndex];
        RtlCopyMemory(entry->Buffer, KeyPath->Buffer, KeyPath->Length);
        entry->Path.Buffer = entry->Buffer;
        entry->Path.Length = KeyPath->Length;
        entry->Path.MaximumLength = sizeof(entry->Buffer);
        entry->InUse = TRUE;
        added = TRUE;
    }

Done:
    ExReleaseFastMutex(&gProtectedRegistryKeysMutex);
    return added;
}

BOOLEAN
KinnectorRemoveProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    BOOLEAN removed = FALSE;
    ULONG i;

    ExAcquireFastMutex(&gProtectedRegistryKeysMutex);
    for (i = 0; i < KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS; i++) {
        if (gProtectedRegistryKeys[i].InUse &&
            RtlEqualUnicodeString(&gProtectedRegistryKeys[i].Path, KeyPath, TRUE)) {
            gProtectedRegistryKeys[i].InUse = FALSE;
            removed = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gProtectedRegistryKeysMutex);
    return removed;
}

BOOLEAN
KinnectorIsProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    BOOLEAN found = FALSE;
    ULONG i;

    if (KeyPath == NULL) {
        return FALSE;
    }

    ExAcquireFastMutex(&gProtectedRegistryKeysMutex);
    for (i = 0; i < KINNECTOR_MAX_PROTECTED_REGISTRY_KEYS; i++) {
        if (gProtectedRegistryKeys[i].InUse &&
            RtlEqualUnicodeString(&gProtectedRegistryKeys[i].Path, KeyPath, TRUE)) {
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gProtectedRegistryKeysMutex);
    return found;
}

VOID
KinnectorProtectedRegistryKeysClear(
    VOID
    )
{
    ExAcquireFastMutex(&gProtectedRegistryKeysMutex);
    RtlZeroMemory(gProtectedRegistryKeys, sizeof(gProtectedRegistryKeys));
    ExReleaseFastMutex(&gProtectedRegistryKeysMutex);
}
