#include "protected_resources.h"

typedef struct _KINNECTOR_PROTECTED_ENTRY {
    KINNECTOR_RESOURCE_KEY Key;
    BOOLEAN InUse;
} KINNECTOR_PROTECTED_ENTRY;

static KSPIN_LOCK gProtectedResourcesLock;
static KINNECTOR_PROTECTED_ENTRY gProtectedResources[KINNECTOR_MAX_PROTECTED_RESOURCES];

static BOOLEAN
KinnectorKeysEqual(
    _In_ const KINNECTOR_RESOURCE_KEY* A,
    _In_ const KINNECTOR_RESOURCE_KEY* B
    )
{
    return A->VolumeSerialNumber == B->VolumeSerialNumber &&
           A->FileReferenceNumber.QuadPart == B->FileReferenceNumber.QuadPart;
}

VOID
KinnectorProtectedResourcesInit(
    VOID
    )
{
    KeInitializeSpinLock(&gProtectedResourcesLock);
    RtlZeroMemory(gProtectedResources, sizeof(gProtectedResources));
}

BOOLEAN
KinnectorAddProtectedResource(
    _In_ ULONG VolumeSerialNumber,
    _In_ LARGE_INTEGER FileReferenceNumber
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KINNECTOR_RESOURCE_KEY key;
    BOOLEAN added = FALSE;
    ULONG i;

    key.VolumeSerialNumber = VolumeSerialNumber;
    key.FileReferenceNumber = FileReferenceNumber;

    KeAcquireInStackQueuedSpinLock(&gProtectedResourcesLock, &lockHandle);

    // Idempotent: adding an already-protected resource again is success,
    // not a duplicate entry.
    for (i = 0; i < KINNECTOR_MAX_PROTECTED_RESOURCES; i++) {
        if (gProtectedResources[i].InUse && KinnectorKeysEqual(&gProtectedResources[i].Key, &key)) {
            added = TRUE;
            goto Done;
        }
    }

    for (i = 0; i < KINNECTOR_MAX_PROTECTED_RESOURCES; i++) {
        if (!gProtectedResources[i].InUse) {
            gProtectedResources[i].Key = key;
            gProtectedResources[i].InUse = TRUE;
            added = TRUE;
            break;
        }
    }

Done:
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return added;
}

BOOLEAN
KinnectorRemoveProtectedResource(
    _In_ ULONG VolumeSerialNumber,
    _In_ LARGE_INTEGER FileReferenceNumber
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KINNECTOR_RESOURCE_KEY key;
    BOOLEAN removed = FALSE;
    ULONG i;

    key.VolumeSerialNumber = VolumeSerialNumber;
    key.FileReferenceNumber = FileReferenceNumber;

    KeAcquireInStackQueuedSpinLock(&gProtectedResourcesLock, &lockHandle);
    for (i = 0; i < KINNECTOR_MAX_PROTECTED_RESOURCES; i++) {
        if (gProtectedResources[i].InUse && KinnectorKeysEqual(&gProtectedResources[i].Key, &key)) {
            gProtectedResources[i].InUse = FALSE;
            removed = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return removed;
}

BOOLEAN
KinnectorIsProtectedResource(
    _In_ ULONG VolumeSerialNumber,
    _In_ LARGE_INTEGER FileReferenceNumber
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KINNECTOR_RESOURCE_KEY key;
    BOOLEAN found = FALSE;
    ULONG i;

    key.VolumeSerialNumber = VolumeSerialNumber;
    key.FileReferenceNumber = FileReferenceNumber;

    KeAcquireInStackQueuedSpinLock(&gProtectedResourcesLock, &lockHandle);
    for (i = 0; i < KINNECTOR_MAX_PROTECTED_RESOURCES; i++) {
        if (gProtectedResources[i].InUse && KinnectorKeysEqual(&gProtectedResources[i].Key, &key)) {
            found = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}

VOID
KinnectorProtectedResourcesClear(
    VOID
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&gProtectedResourcesLock, &lockHandle);
    RtlZeroMemory(gProtectedResources, sizeof(gProtectedResources));
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}
