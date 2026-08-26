// Phase 7 step 1 (WINDOWS_COVERAGE_PLAN.md): "Driver loads, does nothing
// harmful - prove the toolchain end-to-end first." This was deliberately the
// smallest possible real minifilter: registered with the Filter Manager,
// attached nowhere. See [[core_windows_phase7_driver_step1]] for the full
// build+sign+load+Driver-Verifier verification history.
//
// Phase 7 step 2 (this change): "IRP_MJ_CREATE gate against the
// config-driven protected-resource list, using Phase 5's canonical-identity
// resolution (reimplemented as kernel-safe code)." This is a materially
// bigger risk step than step 1: step 1 attached to zero volumes, so nothing
// it did could affect real file I/O. Step 2 attaches to every local NTFS
// disk volume and runs on every single file create on the system. Two
// independent safety layers, mirroring core/CLAUDE.md's Linux
// fanotify/BPF-LSM blocking-mechanism doctrine:
//   1. Fail-open everywhere: any unexpected state (context missing, query
//      failed, file already gone) just lets the create through unmodified.
//      This driver must never accidentally turn into "deny everything."
//   2. gEnforcementEnabled defaults to FALSE. Even a confirmed match against
//      the protected-resource list only logs via DbgPrint until this is
//      explicitly armed - loading this driver must never itself start
//      denying access.
// Scope for this step: local NTFS disk volumes only (FILE_DEVICE_DISK_FILE_
// SYSTEM + FLT_FSTYPE_NTFS). ReFS uses a 128-bit FILE_ID_INFORMATION, a
// different identity shape than the volume-serial+64-bit-FRN pair
// core/src/windows/resource_identity.cpp already established for user mode -
// out of scope until that's reconciled. Network/removable volumes are also
// refused for now, same DO_NOT_ATTACH discipline as everything step 1 already
// refused.
//
// NOT part of this step: the config-driven part of "config-driven
// protected-resource list." protected_resources.h's store exists and is
// queried on every create, but nothing yet feeds it from
// protect-community/configs/antitheft/ - that needs a real usermode<->kernel
// channel (most likely FltCreateCommunicationPort), which is its own
// separately-testable increment, not bundled into this one. Entries are only
// ever seeded here for controlled local testing, never from a hardcoded path
// in DriverEntry - a typo there could protect (and deny access to) something
// system-critical the instant the driver loads.
//
// SAFETY-CRITICAL, read before changing InstanceSetupCallback: if a
// minifilter's FLT_REGISTRATION omits InstanceSetupCallback entirely (NULL),
// the Filter Manager's default behavior is to attach an instance to EVERY
// volume automatically. This driver's InstanceSetupCallback now attaches
// deliberately, but only to local NTFS disk volumes - every other volume
// type still gets an explicit STATUS_FLT_DO_NOT_ATTACH refusal, same as
// step 1 refused everywhere.
//
// Phase 7 step 3a: CmRegisterCallbackEx toolchain proof - "loads, does
// nothing harmful" applied to the registry-callback mechanism specifically,
// the same deliberately-inert first move as step 1 made for the minifilter
// mechanism. Verified 2026-08-26 under real registry load (reads, writes,
// deletes, a 282-service enumeration) with zero issues - see
// [[core_windows_phase7_step3_registry_callback]]. Registered with a
// placeholder Altitude string (gRegistryAltitude below) - registry-callback
// altitudes are a separate Microsoft-managed numbering space from minifilter
// altitudes, and this placeholder is not a real allocation, same caveat as
// the minifilter INF's placeholder 365100.
//
// Phase 7 step 3b (this change): observation-only registry-key protection.
// Handles exactly three notify classes where Argument2's Object field
// already refers to an existing, opened key: RegNtPreSetValueKey,
// RegNtPreDeleteKey, RegNtPreDeleteValueKey. For each, resolves the key's
// canonical NT-native path (e.g. "\REGISTRY\MACHINE\SOFTWARE\...", NOT the
// Win32 "HKLM\..." form - confirmed empirically via NtQueryObject from user
// mode before writing this, not assumed from docs) via
// CmCallbackGetKeyObjectIDEx - the WDK-documented, deadlock-safe way to get
// a key's name from inside a registry callback, since it resolves through
// the configuration manager's own object naming rather than recursing back
// into a registry API that could deadlock on a lock this callback's thread
// may already hold. Every call to CmCallbackGetKeyObjectIDEx is paired with
// CmCallbackReleaseKeyObjectIDEx in every path (match, no-match, and error) -
// this reference must be released or it leaks on every single matching-class
// registry operation system-wide, which at that frequency is a real
// resource-exhaustion/hang risk, not a cosmetic cleanup step.
//
// Deliberately NOT handled yet: RegNtPreCreateKeyEx (create/open). At that
// point the target key doesn't exist as an Object yet - only RootObject for
// the *parent* plus a CompleteName that isn't necessarily a full path.
// Reconstructing a canonical full path from those two pieces safely is real,
// separate design work, scoped out of this sub-step on purpose, not
// forgotten. QueryValueKey/EnumerateKey/QueryKey are also untouched (highest
// -frequency classes; not needed for "protect this key from modification").
//
// Phase 7 step 3c (this change): actual denial for the same three notify
// classes step 3b already resolves identity for. Returning any non-success
// NTSTATUS from a Pre-notification registry callback (unlike FltMgr's
// FLT_PREOP_COMPLETE protocol) tells the configuration manager to fail the
// operation with that status and skip performing it - the mechanism itself
// needed no new IRQL-sensitive code, only a different return value, so this
// change carries none of step 3b's crash-class risk (see
// [[core_windows_phase7_step3b_crash_irql]] for that history).
//
// gRegistryEnforcementEnabled defaults to FALSE, same doctrine as
// gEnforcementEnabled. One deliberate difference from the file gate: that
// flag is a permanent hardcoded FALSE with no wiring to flip it (its deny
// path has never actually been exercised - see
// [[core_windows_phase7_step2_create_gate]]'s open gap). Here, a *test-only*
// registry value (TestRegistryEnforcementEnabled, read once in
// KinnectorLoadTestConfiguration, same temporary scaffolding as everything
// else in that function) can flip it on for a controlled test - because the
// whole point of this step is to actually prove denial works, not just
// compile. It still defaults off with no seed present, same as every other
// blocking mechanism in this codebase, and must never be hardcoded TRUE in
// source.

// Phase 7 step 4 (this change): spoof-proof process lineage via
// PsSetCreateProcessNotifyRoutineEx (NOT the plan doc's literally-named
// "PsSetCreateProcessNotifyRoutineEx2" - checked the actual WDK header
// before writing this, per the plan's own instruction to validate rather
// than assume: Ex2 takes a PSCREATEPROCESSNOTIFYTYPE + PVOID and is for an
// unrelated subsystem-registration purpose; the classic per-process-creation
// callback receiving PS_CREATE_NOTIFY_INFO is the single-"Ex" routine).
// Supersedes Phase 2's ETW-based interim lineage mechanism
// ([[core_windows_phase2_lineage]]) as the authoritative source: the real
// creating process is CreateInfo->CreatingThreadId.UniqueProcess, resolved
// by the kernel from the actual calling thread - NEVER
// CreateInfo->ParentProcessId, which is user-mode-supplied and trivially
// spoofable via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. This distinction is
// verified empirically in this step's own test (see
// KinnectorProcessNotifyCallback's test-observation block below), not just
// assumed from the design doc's claim.
//
// SAFETY-CRITICAL: PS_CREATE_NOTIFY_INFO.CreationStatus is an _Inout_ field
// that this callback COULD set to fail the process creation - this step
// NEVER touches it. Step 4's job is pure lineage observation, not process
// blocking; accidentally writing to CreationStatus here would risk denying
// arbitrary process launches system-wide, a categorically larger blast
// radius than anything steps 1-3 could do (their protected lists default
// empty, so an empty/misconfigured list is inert - there is no equivalent
// "empty and inert" state for accidentally touching CreationStatus).
//
// SAFETY-CRITICAL, learned from [[core_windows_phase7_step3b_crash_irql]]:
// process_lineage.c's store uses a plain KSPIN_LOCK, which is safe here
// specifically because every comparison under it is a pure HANDLE/LONGLONG
// integer compare - never a call into Rtl/Cm/Zw or anything that could
// touch paged memory. PsLookupProcessByProcessId (used to resolve the
// creator's own create-time) is only IRQL-safe up to APC_LEVEL, so it is
// always called *before* acquiring the lock, never while holding it - see
// KinnectorProcessNotifyCallback's ordering below.
//
// Registration gotcha: PsSetCreateProcessNotifyRoutineEx is not scoped to
// this driver's DRIVER_OBJECT - the routine pointer itself is the only
// handle. If this driver unloaded without removing it first, the very next
// process creation anywhere on the system would call into freed driver
// memory. KinnectorFilterUnload unconditionally calls the Remove=TRUE form
// before returning if registration succeeded - Windows blocks that call
// until any in-flight callback invocations finish, so this is safe as long
// as unload always reaches that call, which the existing atomic-teardown
// discipline already guarantees.

// Phase 7 step 9 (this change): raw-volume (\\.\C:) coarse allowlist gate.
// See raw_volume_gate.h for the full scope note - this covers only the
// raw-volume half of step 9's plan line item, not \\.\PhysicalDriveN, which
// needs a separate device-stack attachment this driver doesn't have.
//
// Detection: a create whose target FileObject->FileName is empty (zero
// length) means the caller opened the volume device object itself - e.g.
// "\\.\C:" - rather than any path within its file system. A normal file or
// even the root directory ("\\.\C:\") always carries a non-empty FileName
// at this point; this is the standard, widely-used technique for
// distinguishing a raw-volume open from an ordinary file create at the
// minifilter layer. This check runs before the existing per-file
// FileInternalInformation query, which either doesn't apply to a raw-volume
// open or isn't reliable for one - untested on this driver either way,
// since this step wasn't run against a real \\.\C: handle on a live
// machine (unlike steps 1-4, which each closed with an empirical
// verification pass - see [[core_windows_phase7_progress]]). Flag this
// explicitly rather than claim step 3's level of confidence.
//
// gRawVolumeEnforcementEnabled follows the exact same doctrine as
// gRegistryEnforcementEnabled: defaults FALSE, only a test-only registry
// seed (TestRawVolumeEnforcementEnabled) can flip it, and even when on, an
// empty allowlist means "nothing configured to check against" - fail open,
// never deny. A raw-volume open is only ever denied when enforcement is on,
// the allowlist is non-empty, AND the requesting process's coarse image
// name isn't in it.
#include <fltKernel.h>
#include "protected_resources.h"
#include "protected_registry_keys.h"
#include "process_lineage.h"
#include "raw_volume_gate.h"

// PsGetProcessImageFileName is a real, stable NTOSKRNL export used
// throughout the driver ecosystem (including major AV/EDR products) for
// exactly this kind of coarse process identification, but it isn't
// declared in the public WDK headers this project includes - manual
// declaration is the standard, widely-documented way every other minifilter
// sample handles this. See raw_volume_gate.h for why this is deliberately
// coarse (no path, no signer, ~15 chars, trivially spoofable by process
// naming) rather than a substitute for Phase 5's real signer-based identity
// work.
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

DRIVER_INITIALIZE DriverEntry;
NTSTATUS KinnectorFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS KinnectorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
FLT_PREOP_CALLBACK_STATUS KinnectorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS KinnectorPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

// ---------------------------------------------------------------------
// TEMPORARY, TEST-ONLY seeding + observation mechanism for step 2's manual
// verification pass. This is NOT the real config channel - WINDOWS_COVERAGE_
// PLAN.md Phase 7 step 2 explicitly defers real usermode<->kernel config
// wiring (most likely FltCreateCommunicationPort) to its own later, separately
// -tested increment. This reads two registry values under the service's own
// \Parameters key (populated by hand via `reg add` for this test, never by
// any real caller) to seed exactly one protected-resource entry, and writes
// back one observation flag when a create against it is actually seen -
// enough to prove the identity-resolution and lookup path both fired
// correctly without needing a kernel debugger attached. Delete this whole
// block once the real communication-port mechanism exists.
// ---------------------------------------------------------------------
VOID KinnectorLoadTestConfiguration(_In_ PUNICODE_STRING RegistryPath);
VOID KinnectorRecordTestObservation(VOID);
VOID KinnectorRecordTestRegistryObservation(VOID);
VOID KinnectorRecordTestLineageObservation(
    _In_ HANDLE ChildProcessId,
    _In_ HANDLE ReportedParentProcessId,
    _In_ HANDLE RealCreatorProcessId);
VOID KinnectorRecordTestRawVolumeObservation(_In_ BOOLEAN Denied);

VOID KinnectorHandleRawVolumeOpen(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG VolumeSerialNumber);

EX_CALLBACK_FUNCTION KinnectorRegistryCallback;

VOID KinnectorProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, KinnectorFilterUnload)
#pragma alloc_text(PAGE, KinnectorInstanceSetup)
#endif

// Cached per-instance state - resolved once in InstanceSetupCallback rather
// than re-queried on every single file create (this runs on the hot path of
// every create on every attached volume).
typedef struct _KINNECTOR_INSTANCE_CONTEXT {
    ULONG VolumeSerialNumber;
} KINNECTOR_INSTANCE_CONTEXT, *PKINNECTOR_INSTANCE_CONTEXT;

#define KINNECTOR_POOL_TAG 'lftK'

CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_INSTANCE_CONTEXT,
      0,
      NULL,
      sizeof(KINNECTOR_INSTANCE_CONTEXT),
      KINNECTOR_POOL_TAG,
      NULL,
      NULL,
      NULL },
    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, KinnectorPreCreate, KinnectorPostCreate },
    { IRP_MJ_OPERATION_END }
};

FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),          // Size
    FLT_REGISTRATION_VERSION,          // Version
    0,                                  // Flags
    ContextRegistration,                // ContextRegistration - instance context (cached volume serial)
    Callbacks,                          // OperationRegistration
    KinnectorFilterUnload,              // FilterUnloadCallback
    KinnectorInstanceSetup,             // InstanceSetupCallback - see safety note above
    NULL,                               // InstanceQueryTeardownCallback
    NULL,                               // InstanceTeardownStartCallback
    NULL,                               // InstanceTeardownCompleteCallback
    NULL,                               // GenerateFileNameCallback
    NULL,                               // NormalizeNameComponentCallback
    NULL,                               // NormalizeContextCleanupCallback
    NULL,                               // TransactionNotificationCallback
    NULL,                               // NormalizeNameComponentExCallback
    NULL                                // SectionNotificationCallback
};

PFLT_FILTER gFilterHandle = NULL;

// Defaults to off. Matches this workspace's established doctrine for any
// blocking mechanism (core/CLAUDE.md's fanotify/BPF-LSM rule, same principle
// applied here): loading this driver, even with protected-resource entries
// present, must never itself start denying access until explicitly armed.
BOOLEAN gEnforcementEnabled = FALSE;

// Registry-gate equivalent of gEnforcementEnabled above - see the file-level
// step 3c note for why this one is test-toggleable while the file gate's
// isn't. Defaults off; only KinnectorLoadTestConfiguration's test-only
// registry seed can flip it, and only for a deliberately-controlled test.
BOOLEAN gRegistryEnforcementEnabled = FALSE;

// Raw-volume gate equivalent of gRegistryEnforcementEnabled - see this
// file's step 9 scope note and raw_volume_gate.h for the full doctrine.
// Defaults off; test-only registry seed only.
BOOLEAN gRawVolumeEnforcementEnabled = FALSE;

// PLACEHOLDER - registry-callback altitudes are a separate Microsoft-managed
// numbering space from minifilter altitudes (see core/driver/kinnector_filter/
// kinnector_filter.inf's own placeholder-altitude caveat for the file-gate
// side). Not a real allocation; fine for local testsigning-mode testing only.
static UNICODE_STRING gRegistryAltitude = RTL_CONSTANT_STRING(L"320000");
static LARGE_INTEGER gRegistryCallbackCookie;
static BOOLEAN gRegistryCallbackRegistered = FALSE;

static BOOLEAN gProcessNotifyRegistered = FALSE;

NTSTATUS
KinnectorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    NTSTATUS status;
    PKINNECTOR_INSTANCE_CONTEXT context = NULL;
    IO_STATUS_BLOCK iosb;
    UCHAR volInfoBuffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 128];
    PFILE_FS_VOLUME_INFORMATION volInfo = (PFILE_FS_VOLUME_INFORMATION)volInfoBuffer;

    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    // Step 2 scope: local NTFS disk volumes only - see the file-level scope
    // note above for why. Refuse everywhere else, same discipline as step 1.
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM ||
        VolumeFilesystemType != FLT_FSTYPE_NTFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    RtlZeroMemory(volInfoBuffer, sizeof(volInfoBuffer));
    status = FltQueryVolumeInformation(
        FltObjects->Instance,
        &iosb,
        volInfo,
        sizeof(volInfoBuffer),
        FileFsVolumeInformation);

    // STATUS_BUFFER_OVERFLOW is expected/harmless here - it only means the
    // variable-length volume label at the end didn't fit. VolumeSerialNumber
    // is a fixed-offset field earlier in the struct and is always written
    // first; it's the only field this driver reads.
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    status = FltAllocateContext(
        gFilterHandle,
        FLT_INSTANCE_CONTEXT,
        sizeof(KINNECTOR_INSTANCE_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&context);
    if (!NT_SUCCESS(status)) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    context->VolumeSerialNumber = volInfo->VolumeSerialNumber;

    status = FltSetInstanceContext(
        FltObjects->Instance,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        context,
        NULL);

    FltReleaseContext(context);

    if (!NT_SUCCESS(status)) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
KinnectorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    // All real logic lives in the post-create callback, where the create has
    // already completed and there's a real FILE_OBJECT to query an identity
    // from - a target file often doesn't have a queryable identity yet at
    // pre-create time. This callback exists only to ask FltMgr for that
    // post-create callback.
    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
KinnectorPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PKINNECTOR_INSTANCE_CONTEXT instanceContext = NULL;
    KINNECTOR_RESOURCE_KEY key;
    UCHAR internalInfoBuffer[sizeof(FILE_INTERNAL_INFORMATION)];
    PFILE_INTERNAL_INFORMATION internalInfo = (PFILE_INTERNAL_INFORMATION)internalInfoBuffer;
    ULONG lengthReturned;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Fail-open on every unusual condition below: never let a bug in this
    // gate turn into a system-wide file-access outage. Only ever deny when
    // every resolution step below succeeds AND the identity is a confirmed
    // match against the protected-resource list.
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        // Create already failed for its own reason - nothing to gate.
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT*)&instanceContext);
    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Step 9: a raw-volume open ("\\.\C:") has no path component at all -
    // see the file-level scope note above for why this check has to come
    // before, and instead of, the per-file identity resolution below.
    if (FltObjects->FileObject->FileName.Length == 0) {
        KinnectorHandleRawVolumeOpen(Data, instanceContext->VolumeSerialNumber);
        FltReleaseContext(instanceContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        internalInfo,
        sizeof(internalInfoBuffer),
        FileInternalInformation,
        &lengthReturned);

    if (!NT_SUCCESS(status)) {
        FltReleaseContext(instanceContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    key.VolumeSerialNumber = instanceContext->VolumeSerialNumber;
    key.FileReferenceNumber = internalInfo->IndexNumber;

    FltReleaseContext(instanceContext);

    if (KinnectorIsProtectedResource(key.VolumeSerialNumber, key.FileReferenceNumber)) {
        DbgPrint(
            "kinnector_filter: protected-resource CREATE observed (vol=0x%08lX frn=0x%016llX) enforcement=%d\n",
            key.VolumeSerialNumber,
            key.FileReferenceNumber.QuadPart,
            gEnforcementEnabled);

        KinnectorRecordTestObservation();

        if (gEnforcementEnabled) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

static BOOLEAN gTestModeActive = FALSE;
static WCHAR gTestParametersPathBuffer[260];
static UNICODE_STRING gTestParametersPath;

// Step 4 test-only lineage watch: when non-empty, KinnectorProcessNotify
// Callback records observation values for the first process it sees whose
// image name ends with this suffix - see that callback's own comment block
// for what gets recorded and why.
static WCHAR gTestLineageWatchSuffixBuffer[128];
static UNICODE_STRING gTestLineageWatchSuffix;

VOID
KinnectorLoadTestConfiguration(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING valueName;
    UCHAR buffer[64];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG resultLength;
    ULONG volumeSerial = 0;
    LARGE_INTEGER frn;
    BOOLEAN haveVolumeSerial = FALSE;
    BOOLEAN haveFrn = FALSE;

    frn.QuadPart = 0;

    if ((ULONG)RegistryPath->Length + sizeof(L"\\Parameters") > sizeof(gTestParametersPathBuffer)) {
        return;
    }

    RtlInitEmptyUnicodeString(&gTestParametersPath, gTestParametersPathBuffer, sizeof(gTestParametersPathBuffer));
    RtlCopyUnicodeString(&gTestParametersPath, RegistryPath);
    RtlAppendUnicodeToString(&gTestParametersPath, L"\\Parameters");

    InitializeObjectAttributes(&objAttrs, &gTestParametersPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ | KEY_SET_VALUE, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return;  // no \Parameters key present - normal, non-test load
    }

    RtlInitUnicodeString(&valueName, L"TestProtectedVolumeSerial");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, info, sizeof(buffer), &resultLength);
    if (NT_SUCCESS(status) && info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)) {
        RtlCopyMemory(&volumeSerial, info->Data, sizeof(ULONG));
        haveVolumeSerial = TRUE;
    }

    RtlInitUnicodeString(&valueName, L"TestProtectedFileReferenceNumber");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, info, sizeof(buffer), &resultLength);
    if (NT_SUCCESS(status) && info->Type == REG_QWORD && info->DataLength == sizeof(ULONGLONG)) {
        RtlCopyMemory(&frn.QuadPart, info->Data, sizeof(ULONGLONG));
        haveFrn = TRUE;
    }

    if (haveVolumeSerial && haveFrn) {
        KinnectorAddProtectedResource(volumeSerial, frn);
        gTestModeActive = TRUE;
    }

    // Optional second seed, same \Parameters key: a registry key path to
    // protect for step 3b's testing (REG_SZ, NT-native form e.g.
    // "\REGISTRY\MACHINE\SOFTWARE\..." - see the file-level scope note on
    // KinnectorRegistryCallback for why that form, not "HKLM\...").
    {
        UCHAR pathBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KINNECTOR_REGISTRY_KEY_PATH_MAX_CHARS * sizeof(WCHAR)];
        PKEY_VALUE_PARTIAL_INFORMATION pathInfo = (PKEY_VALUE_PARTIAL_INFORMATION)pathBuffer;
        UNICODE_STRING keyPath;

        RtlInitUnicodeString(&valueName, L"TestProtectedRegistryKeyPath");
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, pathInfo, sizeof(pathBuffer), &resultLength);
        if (NT_SUCCESS(status) && pathInfo->Type == REG_SZ && pathInfo->DataLength >= sizeof(WCHAR)) {
            USHORT dataLength = (USHORT)pathInfo->DataLength;
            PWCH chars = (PWCH)pathInfo->Data;
            // REG_SZ DataLength conventionally includes the null terminator,
            // but that's not guaranteed by every writer - only trim it if
            // it's actually there, rather than blindly subtracting sizeof(WCHAR).
            if (dataLength >= sizeof(WCHAR) && chars[dataLength / sizeof(WCHAR) - 1] == L'\0') {
                dataLength -= sizeof(WCHAR);
            }
            keyPath.Buffer = chars;
            keyPath.Length = dataLength;
            keyPath.MaximumLength = (USHORT)pathInfo->DataLength;
            KinnectorAddProtectedRegistryKey(&keyPath);
            gTestModeActive = TRUE;
        }
    }

    // Third optional seed, same \Parameters key: a REG_DWORD test-only
    // toggle for gRegistryEnforcementEnabled (step 3c) - see the file-level
    // scope note on gRegistryEnforcementEnabled for why this one, unlike
    // gEnforcementEnabled, has a way to be flipped on at all.
    {
        UCHAR enforceBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION enforceInfo = (PKEY_VALUE_PARTIAL_INFORMATION)enforceBuffer;
        ULONG enforceValue = 0;

        RtlInitUnicodeString(&valueName, L"TestRegistryEnforcementEnabled");
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, enforceInfo, sizeof(enforceBuffer), &resultLength);
        if (NT_SUCCESS(status) && enforceInfo->Type == REG_DWORD && enforceInfo->DataLength == sizeof(ULONG)) {
            RtlCopyMemory(&enforceValue, enforceInfo->Data, sizeof(ULONG));
            if (enforceValue != 0) {
                gRegistryEnforcementEnabled = TRUE;
            }
        }
    }

    // Fourth optional seed, same \Parameters key: step 4's lineage-watch
    // image-name suffix (REG_SZ) - see gTestLineageWatchSuffix's declaration
    // for what this drives.
    {
        UCHAR suffixBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(gTestLineageWatchSuffixBuffer)];
        PKEY_VALUE_PARTIAL_INFORMATION suffixInfo = (PKEY_VALUE_PARTIAL_INFORMATION)suffixBuffer;

        RtlInitUnicodeString(&valueName, L"TestLineageWatchImageNameSuffix");
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, suffixInfo, sizeof(suffixBuffer), &resultLength);
        if (NT_SUCCESS(status) && suffixInfo->Type == REG_SZ && suffixInfo->DataLength >= sizeof(WCHAR) &&
            suffixInfo->DataLength <= sizeof(gTestLineageWatchSuffixBuffer)) {
            USHORT dataLength = (USHORT)suffixInfo->DataLength;
            PWCH chars = (PWCH)suffixInfo->Data;
            if (dataLength >= sizeof(WCHAR) && chars[dataLength / sizeof(WCHAR) - 1] == L'\0') {
                dataLength -= sizeof(WCHAR);
            }
            RtlCopyMemory(gTestLineageWatchSuffixBuffer, chars, dataLength);
            gTestLineageWatchSuffix.Buffer = gTestLineageWatchSuffixBuffer;
            gTestLineageWatchSuffix.Length = dataLength;
            gTestLineageWatchSuffix.MaximumLength = sizeof(gTestLineageWatchSuffixBuffer);
            gTestModeActive = TRUE;
        }
    }

    // Fifth optional seed, same \Parameters key: step 9's raw-volume
    // allowlist entry (REG_SZ, a short ANSI-range image file name e.g.
    // "chkdsk.exe" - see raw_volume_gate.h for why this is a bare image
    // name, not a path). Registry REG_SZ values are UTF-16; converted here
    // with a plain truncating narrow-copy since every real entry is
    // expected to be pure ASCII (matching PsGetProcessImageFileName's own
    // ANSI-only output) - not a general Unicode-to-ANSI conversion.
    {
        UCHAR allowlistBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KINNECTOR_IMAGE_NAME_MAX_CHARS * sizeof(WCHAR)];
        PKEY_VALUE_PARTIAL_INFORMATION allowlistInfo = (PKEY_VALUE_PARTIAL_INFORMATION)allowlistBuffer;
        CHAR ansiName[KINNECTOR_IMAGE_NAME_MAX_CHARS];
        ULONG charCount;
        ULONG j;

        RtlInitUnicodeString(&valueName, L"TestRawVolumeAllowlistImageName");
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, allowlistInfo, sizeof(allowlistBuffer), &resultLength);
        if (NT_SUCCESS(status) && allowlistInfo->Type == REG_SZ && allowlistInfo->DataLength >= sizeof(WCHAR)) {
            PWCH chars = (PWCH)allowlistInfo->Data;

            charCount = allowlistInfo->DataLength / sizeof(WCHAR);
            if (charCount >= KINNECTOR_IMAGE_NAME_MAX_CHARS) {
                charCount = KINNECTOR_IMAGE_NAME_MAX_CHARS - 1;
            }

            RtlZeroMemory(ansiName, sizeof(ansiName));
            for (j = 0; j < charCount && chars[j] != L'\0'; j++) {
                ansiName[j] = (CHAR)(chars[j] & 0x7F);
            }

            if (ansiName[0] != '\0') {
                KinnectorAddRawVolumeAllowlistEntry(ansiName);
                gTestModeActive = TRUE;
            }
        }
    }

    // Sixth optional seed, same \Parameters key: step 9's
    // gRawVolumeEnforcementEnabled toggle - same pattern as
    // TestRegistryEnforcementEnabled above.
    {
        UCHAR enforceBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION enforceInfo = (PKEY_VALUE_PARTIAL_INFORMATION)enforceBuffer;
        ULONG enforceValue = 0;

        RtlInitUnicodeString(&valueName, L"TestRawVolumeEnforcementEnabled");
        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, enforceInfo, sizeof(enforceBuffer), &resultLength);
        if (NT_SUCCESS(status) && enforceInfo->Type == REG_DWORD && enforceInfo->DataLength == sizeof(ULONG)) {
            RtlCopyMemory(&enforceValue, enforceInfo->Data, sizeof(ULONG));
            if (enforceValue != 0) {
                gRawVolumeEnforcementEnabled = TRUE;
            }
        }
    }

    ZwClose(keyHandle);
}

VOID
KinnectorRecordTestObservation(
    VOID
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING valueName;
    ULONG value = 1;

    if (!gTestModeActive) {
        return;
    }

    InitializeObjectAttributes(&objAttrs, &gTestParametersPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"TestObservedMatch");
    ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));
    ZwClose(keyHandle);
}

VOID
KinnectorRecordTestRegistryObservation(
    VOID
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING valueName;
    ULONG value = 1;

    if (!gTestModeActive) {
        return;
    }

    // This ZwSetValueKey call is itself a RegNtPreSetValueKey operation on
    // our own \Parameters key, so it re-enters KinnectorRegistryCallback
    // once, harmlessly - \Parameters is never itself in the protected-key
    // list, so KinnectorIsProtectedRegistryKey returns FALSE for it and this
    // does not recurse further. Do not add \Parameters (or any ancestor of
    // it) to the protected list for testing, or this would loop.
    InitializeObjectAttributes(&objAttrs, &gTestParametersPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"TestObservedRegistryMatch");
    ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));
    ZwClose(keyHandle);
}

VOID
KinnectorRecordTestRawVolumeObservation(
    _In_ BOOLEAN Denied
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING valueName;
    ULONG value = 1;

    if (!gTestModeActive) {
        return;
    }

    InitializeObjectAttributes(&objAttrs, &gTestParametersPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"TestRawVolumeObserved");
    ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));

    if (Denied) {
        RtlInitUnicodeString(&valueName, L"TestRawVolumeDenied");
        ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));
    }

    ZwClose(keyHandle);
}

VOID
KinnectorHandleRawVolumeOpen(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG VolumeSerialNumber
    )
{
    PCHAR imageFileName;
    BOOLEAN allowlisted = TRUE;
    BOOLEAN allowlistEmpty;
    BOOLEAN deny = FALSE;

    // Fail-open: no image name to check against means nothing to deny.
    // PsGetProcessImageFileName can return NULL for processes with no
    // image (e.g. System) - never treat that as grounds to block.
    imageFileName = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (imageFileName == NULL) {
        return;
    }

    allowlistEmpty = KinnectorRawVolumeAllowlistIsEmpty();
    if (!allowlistEmpty) {
        allowlisted = KinnectorIsRawVolumeAllowlisted(imageFileName);
    }

    DbgPrint(
        "kinnector_filter: raw-volume OPEN observed (vol=0x%08lX image=%s allowlisted=%d enforcement=%d)\n",
        VolumeSerialNumber,
        imageFileName,
        allowlisted,
        gRawVolumeEnforcementEnabled);

    // Only ever deny when enforcement is on, an allowlist has actually been
    // configured, AND this specific caller isn't on it - an empty allowlist
    // is inert, same discipline as every other blocking mechanism in this
    // driver (see gEnforcementEnabled's file-level note).
    if (gRawVolumeEnforcementEnabled && !allowlistEmpty && !allowlisted) {
        deny = TRUE;
    }

    KinnectorRecordTestRawVolumeObservation(deny);

    if (deny) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
    }
}

static BOOLEAN
KinnectorImageNameEndsWithWatchSuffix(
    _In_opt_ PCUNICODE_STRING ImageFileName
    )
{
    UNICODE_STRING tail;

    if (ImageFileName == NULL || gTestLineageWatchSuffix.Length == 0) {
        return FALSE;
    }
    if (ImageFileName->Length < gTestLineageWatchSuffix.Length) {
        return FALSE;
    }

    tail.Buffer = (PWCH)((PUCHAR)ImageFileName->Buffer + (ImageFileName->Length - gTestLineageWatchSuffix.Length));
    tail.Length = gTestLineageWatchSuffix.Length;
    tail.MaximumLength = tail.Length;

    return RtlEqualUnicodeString(&tail, &gTestLineageWatchSuffix, TRUE);
}

VOID
KinnectorRecordTestLineageObservation(
    _In_ HANDLE ChildProcessId,
    _In_ HANDLE ReportedParentProcessId,
    _In_ HANDLE RealCreatorProcessId
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING valueName;
    ULONG value;

    if (!gTestModeActive) {
        return;
    }

    InitializeObjectAttributes(&objAttrs, &gTestParametersPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return;
    }

    value = HandleToULong(ChildProcessId);
    RtlInitUnicodeString(&valueName, L"TestLineageChildPid");
    ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));

    value = HandleToULong(ReportedParentProcessId);
    RtlInitUnicodeString(&valueName, L"TestLineageReportedParentPid");
    ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));

    value = HandleToULong(RealCreatorProcessId);
    RtlInitUnicodeString(&valueName, L"TestLineageRealCreatorPid");
    ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &value, sizeof(value));

    ZwClose(keyHandle);
}

VOID
KinnectorProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    LONGLONG childCreateTime;
    HANDLE creatorProcessId;
    LONGLONG creatorCreateTime;
    PEPROCESS creatorProcess = NULL;
    NTSTATUS lookupStatus;

    childCreateTime = PsGetProcessCreateTimeQuadPart(Process);

    if (CreateInfo == NULL) {
        // Process exit - prune the lineage entry so the table doesn't grow
        // unbounded. Harmless no-op if this process was never recorded
        // (table was full, or creator-lookup failed at create time).
        KinnectorRemoveProcessLineage(ProcessId, childCreateTime);
        return;
    }

    // CREATE. Deliberately never reads from or writes to
    // CreateInfo->CreationStatus - see the file-level safety note above.
    creatorProcessId = CreateInfo->CreatingThreadId.UniqueProcess;

    // Resolve the creator's own create-time before acquiring any lock -
    // PsLookupProcessByProcessId is IRQL-safe only up to APC_LEVEL, and
    // process_lineage.c's KSPIN_LOCK raises to DISPATCH_LEVEL. Fail-open: if
    // the creator has already exited (a normal race - e.g. a short-lived
    // launcher), just skip recording lineage for this one child.
    lookupStatus = PsLookupProcessByProcessId(creatorProcessId, &creatorProcess);
    if (NT_SUCCESS(lookupStatus)) {
        creatorCreateTime = PsGetProcessCreateTimeQuadPart(creatorProcess);
        ObDereferenceObject(creatorProcess);
        KinnectorRecordProcessLineage(ProcessId, childCreateTime, creatorProcessId, creatorCreateTime);
    }

    // ---------------------------------------------------------------------
    // TEMPORARY, TEST-ONLY observation for step 4's empirical spoofing test
    // (see gTestLineageWatchSuffix). Records both the possibly-spoofed
    // reported parent and the real creator PID when a watched process is
    // seen - this is what proves (or disproves) on this real machine that
    // CreatingThreadId resists PROC_THREAD_ATTRIBUTE_PARENT_PROCESS spoofing
    // while ParentProcessId doesn't, rather than just trusting the design
    // doc's claim.
    // ---------------------------------------------------------------------
    if (KinnectorImageNameEndsWithWatchSuffix(CreateInfo->ImageFileName)) {
        KinnectorRecordTestLineageObservation(ProcessId, CreateInfo->ParentProcessId, creatorProcessId);
    }
}

NTSTATUS
KinnectorRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;
    PVOID targetObject = NULL;
    PCUNICODE_STRING objectName = NULL;
    NTSTATUS nameStatus;
    NTSTATUS resultStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(CallbackContext);

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Step 3b scope: only the three notify classes where Argument2's Object
    // field already refers to an existing, opened key - see the file-level
    // scope note above for why create/open isn't handled yet. Every other
    // notify class (query, enumerate, create/open, flush, load/unload,
    // rename, ...) falls through untouched, same as step 3a.
    switch (notifyClass) {
        case RegNtPreSetValueKey:
            if (Argument2 != NULL) {
                targetObject = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object;
            }
            break;
        case RegNtPreDeleteKey:
            if (Argument2 != NULL) {
                targetObject = ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object;
            }
            break;
        case RegNtPreDeleteValueKey:
            if (Argument2 != NULL) {
                targetObject = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object;
            }
            break;
        default:
            return STATUS_SUCCESS;
    }

    if (targetObject == NULL) {
        return STATUS_SUCCESS;
    }

    nameStatus = CmCallbackGetKeyObjectIDEx(&gRegistryCallbackCookie, targetObject, NULL, &objectName, 0);
    if (!NT_SUCCESS(nameStatus) || objectName == NULL) {
        // Fail-open: can't resolve an identity, so there's nothing to match
        // against - never deny (nor even log) on a resolution failure.
        return STATUS_SUCCESS;
    }

    if (KinnectorIsProtectedRegistryKey(objectName)) {
        DbgPrint(
            "kinnector_filter: protected registry key operation observed (class=%d name=%wZ) enforcement=%d\n",
            (int)notifyClass,
            objectName,
            gRegistryEnforcementEnabled);
        KinnectorRecordTestRegistryObservation();

        if (gRegistryEnforcementEnabled) {
            resultStatus = STATUS_ACCESS_DENIED;
        }
    }

    // Release happens unconditionally, whether or not this call is about to
    // deny the operation - the reference must never leak on any path.
    CmCallbackReleaseKeyObjectIDEx(objectName);

    return resultStatus;
}

NTSTATUS
KinnectorFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    if (gProcessNotifyRegistered) {
        // Blocks until any in-flight callback invocations finish - safe and
        // required before this driver's memory goes away. See the
        // file-level "Registration gotcha" note above.
        PsSetCreateProcessNotifyRoutineEx(KinnectorProcessNotifyCallback, TRUE);
        gProcessNotifyRegistered = FALSE;
    }

    if (gRegistryCallbackRegistered) {
        CmUnRegisterCallback(gRegistryCallbackCookie);
        gRegistryCallbackRegistered = FALSE;
    }

    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    KinnectorProtectedResourcesInit();
    KinnectorProtectedRegistryKeysInit();
    KinnectorProcessLineageInit();
    KinnectorRawVolumeGateInit();
    KinnectorLoadTestConfiguration(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = CmRegisterCallbackEx(
        KinnectorRegistryCallback,
        &gRegistryAltitude,
        DriverObject,
        NULL,
        &gRegistryCallbackCookie,
        NULL);
    if (!NT_SUCCESS(status)) {
        // Atomic load, same discipline as the rest of DriverEntry: if any
        // registered mechanism fails to come up, don't leave the driver
        // running with a partial feature set - tear everything back down.
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }
    gRegistryCallbackRegistered = TRUE;

    status = PsSetCreateProcessNotifyRoutineEx(KinnectorProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        // Same atomic-load discipline as the rest of DriverEntry.
        CmUnRegisterCallback(gRegistryCallbackCookie);
        gRegistryCallbackRegistered = FALSE;
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }
    gProcessNotifyRegistered = TRUE;

    return STATUS_SUCCESS;
}
