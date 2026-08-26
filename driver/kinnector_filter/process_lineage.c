#include "process_lineage.h"

typedef struct _KINNECTOR_LINEAGE_ENTRY {
    HANDLE ChildProcessId;
    LONGLONG ChildCreateTime;
    HANDLE CreatorProcessId;
    LONGLONG CreatorCreateTime;
    BOOLEAN InUse;
} KINNECTOR_LINEAGE_ENTRY;

static KSPIN_LOCK gProcessLineageLock;
static KINNECTOR_LINEAGE_ENTRY gProcessLineage[KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES];

static BOOLEAN
KinnectorKeyMatches(
    _In_ const KINNECTOR_LINEAGE_ENTRY* Entry,
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime
    )
{
    return Entry->ChildProcessId == ProcessId && Entry->ChildCreateTime == CreateTime;
}

VOID
KinnectorProcessLineageInit(
    VOID
    )
{
    KeInitializeSpinLock(&gProcessLineageLock);
    RtlZeroMemory(gProcessLineage, sizeof(gProcessLineage));
}

BOOLEAN
KinnectorRecordProcessLineage(
    _In_ HANDLE ChildProcessId,
    _In_ LONGLONG ChildCreateTime,
    _In_ HANDLE CreatorProcessId,
    _In_ LONGLONG CreatorCreateTime
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN recorded = FALSE;
    ULONG i;
    ULONG freeIndex = KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES;

    KeAcquireInStackQueuedSpinLock(&gProcessLineageLock, &lockHandle);

    for (i = 0; i < KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES; i++) {
        if (gProcessLineage[i].InUse && KinnectorKeyMatches(&gProcessLineage[i], ChildProcessId, ChildCreateTime)) {
            freeIndex = i;
            break;
        }
        if (freeIndex == KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES && !gProcessLineage[i].InUse) {
            freeIndex = i;
        }
    }

    if (freeIndex < KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES) {
        gProcessLineage[freeIndex].ChildProcessId = ChildProcessId;
        gProcessLineage[freeIndex].ChildCreateTime = ChildCreateTime;
        gProcessLineage[freeIndex].CreatorProcessId = CreatorProcessId;
        gProcessLineage[freeIndex].CreatorCreateTime = CreatorCreateTime;
        gProcessLineage[freeIndex].InUse = TRUE;
        recorded = TRUE;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return recorded;
}

BOOLEAN
KinnectorRemoveProcessLineage(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN removed = FALSE;
    ULONG i;

    KeAcquireInStackQueuedSpinLock(&gProcessLineageLock, &lockHandle);
    for (i = 0; i < KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES; i++) {
        if (gProcessLineage[i].InUse && KinnectorKeyMatches(&gProcessLineage[i], ProcessId, CreateTime)) {
            gProcessLineage[i].InUse = FALSE;
            removed = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return removed;
}

BOOLEAN
KinnectorLookupProcessLineage(
    _In_ HANDLE ProcessId,
    _In_ LONGLONG CreateTime,
    _Out_ HANDLE* OutCreatorProcessId,
    _Out_ LONGLONG* OutCreatorCreateTime
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN found = FALSE;
    ULONG i;

    KeAcquireInStackQueuedSpinLock(&gProcessLineageLock, &lockHandle);
    for (i = 0; i < KINNECTOR_MAX_PROCESS_LINEAGE_ENTRIES; i++) {
        if (gProcessLineage[i].InUse && KinnectorKeyMatches(&gProcessLineage[i], ProcessId, CreateTime)) {
            *OutCreatorProcessId = gProcessLineage[i].CreatorProcessId;
            *OutCreatorCreateTime = gProcessLineage[i].CreatorCreateTime;
            found = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}

VOID
KinnectorProcessLineageClear(
    VOID
    )
{
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&gProcessLineageLock, &lockHandle);
    RtlZeroMemory(gProcessLineage, sizeof(gProcessLineage));
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}
