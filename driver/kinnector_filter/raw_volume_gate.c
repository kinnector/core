#include "raw_volume_gate.h"

typedef struct _KINNECTOR_RAW_VOLUME_ALLOWLIST_ENTRY {
    CHAR ImageFileName[KINNECTOR_IMAGE_NAME_MAX_CHARS];
    BOOLEAN InUse;
} KINNECTOR_RAW_VOLUME_ALLOWLIST_ENTRY;

static KSPIN_LOCK gRawVolumeAllowlistLock;
static KINNECTOR_RAW_VOLUME_ALLOWLIST_ENTRY gRawVolumeAllowlist[KINNECTOR_MAX_RAW_VOLUME_ALLOWLIST];
static volatile LONG gRawVolumeAllowlistCount = 0;

// Case-insensitive, fixed-width compare - RtlEqualString isn't used here
// since neither input is guaranteed to carry a Length that matches its
// actual content past the first NUL (PsGetProcessImageFileName's buffer is
// a fixed 16 bytes, not a counted string).
static BOOLEAN
KinnectorImageNamesEqual(
    _In_ PCCH A,
    _In_ PCCH B
    )
{
    ULONG i;

    for (i = 0; i < KINNECTOR_IMAGE_NAME_MAX_CHARS; i++) {
        CHAR ca = A[i];
        CHAR cb = B[i];

        if (ca >= 'A' && ca <= 'Z') {
            ca = (CHAR)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (CHAR)(cb - 'A' + 'a');
        }

        if (ca != cb) {
            return FALSE;
        }
        if (ca == '\0') {
            return TRUE;
        }
    }

    return TRUE;
}

VOID
KinnectorRawVolumeGateInit(
    VOID
    )
{
    KeInitializeSpinLock(&gRawVolumeAllowlistLock);
    RtlZeroMemory(gRawVolumeAllowlist, sizeof(gRawVolumeAllowlist));
    gRawVolumeAllowlistCount = 0;
}

BOOLEAN
KinnectorAddRawVolumeAllowlistEntry(
    _In_ PCCH ImageFileName
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN added = FALSE;
    ULONG i;

    KeAcquireInStackQueuedSpinLock(&gRawVolumeAllowlistLock, &lockHandle);

    // Idempotent, same discipline as KinnectorAddProtectedResource.
    for (i = 0; i < KINNECTOR_MAX_RAW_VOLUME_ALLOWLIST; i++) {
        if (gRawVolumeAllowlist[i].InUse &&
            KinnectorImageNamesEqual(gRawVolumeAllowlist[i].ImageFileName, ImageFileName)) {
            added = TRUE;
            goto Done;
        }
    }

    for (i = 0; i < KINNECTOR_MAX_RAW_VOLUME_ALLOWLIST; i++) {
        if (!gRawVolumeAllowlist[i].InUse) {
            RtlZeroMemory(gRawVolumeAllowlist[i].ImageFileName, sizeof(gRawVolumeAllowlist[i].ImageFileName));
            RtlCopyMemory(
                gRawVolumeAllowlist[i].ImageFileName,
                ImageFileName,
                KINNECTOR_IMAGE_NAME_MAX_CHARS - 1);
            gRawVolumeAllowlist[i].InUse = TRUE;
            added = TRUE;
            InterlockedIncrement(&gRawVolumeAllowlistCount);
            break;
        }
    }

Done:
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return added;
}

BOOLEAN
KinnectorRawVolumeAllowlistIsEmpty(
    VOID
    )
{
    // Read without the lock - a torn read here can only ever be stale by
    // one entry for one instant, and the caller-facing contract is only
    // "empty means fail-open," which stays true on either side of that
    // race. No caller depends on this being exact.
    return gRawVolumeAllowlistCount == 0;
}

BOOLEAN
KinnectorIsRawVolumeAllowlisted(
    _In_ PCCH ImageFileName
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN found = FALSE;
    ULONG i;

    KeAcquireInStackQueuedSpinLock(&gRawVolumeAllowlistLock, &lockHandle);
    for (i = 0; i < KINNECTOR_MAX_RAW_VOLUME_ALLOWLIST; i++) {
        if (gRawVolumeAllowlist[i].InUse &&
            KinnectorImageNamesEqual(gRawVolumeAllowlist[i].ImageFileName, ImageFileName)) {
            found = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}

VOID
KinnectorRawVolumeGateClear(
    VOID
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&gRawVolumeAllowlistLock, &lockHandle);
    RtlZeroMemory(gRawVolumeAllowlist, sizeof(gRawVolumeAllowlist));
    gRawVolumeAllowlistCount = 0;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}
