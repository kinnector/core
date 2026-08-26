#include "tamper_unlock.h"
#include <bcrypt.h>

// Kernel-mode CNG (Cryptography API: Next Generation) - the same bcrypt.h
// declarations usermode code uses, confirmed supported in kernel builds
// via this WDK's shared/bcrypt.h (KERNEL_MODE_CNG-guarded sections).
// Linked via ksecdd.lib, added to kinnector_filter.vcxproj's
// AdditionalDependencies alongside fltMgr.lib.

static NTSTATUS
KinnectorComputeSha256(
    _In_reads_bytes_(DataLength) PUCHAR Data,
    _In_ ULONG DataLength,
    _Out_writes_bytes_(KINNECTOR_SHA256_HASH_LENGTH) PUCHAR Hash
    )
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE algHandle = NULL;
    BCRYPT_HASH_HANDLE hashHandle = NULL;

    status = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptCreateHash(algHandle, &hashHandle, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        return status;
    }

    status = BCryptHashData(hashHandle, Data, DataLength, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hashHandle, Hash, KINNECTOR_SHA256_HASH_LENGTH, 0);
    }

    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(algHandle, 0);
    return status;
}

BOOLEAN
KinnectorCheckTamperUnlockPassword(
    _In_ PUNICODE_STRING ParametersKeyPath
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING valueName;
    UCHAR attemptBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256 * sizeof(WCHAR)];
    PKEY_VALUE_PARTIAL_INFORMATION attemptInfo = (PKEY_VALUE_PARTIAL_INFORMATION)attemptBuffer;
    UCHAR hashBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KINNECTOR_SHA256_HASH_LENGTH];
    PKEY_VALUE_PARTIAL_INFORMATION hashInfo = (PKEY_VALUE_PARTIAL_INFORMATION)hashBuffer;
    ULONG resultLength;
    UCHAR computedHash[KINNECTOR_SHA256_HASH_LENGTH];
    BOOLEAN matched = FALSE;

    PAGED_CODE();

    InitializeObjectAttributes(&objAttrs, ParametersKeyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ | KEY_SET_VALUE, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&valueName, L"TamperProtectionUnlockAttempt");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, attemptInfo, sizeof(attemptBuffer), &resultLength);
    if (!NT_SUCCESS(status) || attemptInfo->Type != REG_SZ || attemptInfo->DataLength < sizeof(WCHAR)) {
        ZwClose(keyHandle);
        return FALSE;
    }

    // One-shot: clear the attempt immediately after reading it, whether or
    // not it turns out to match - never let a password attempt linger in
    // the registry past the single check it's for.
    ZwDeleteValueKey(keyHandle, &valueName);

    RtlInitUnicodeString(&valueName, L"TamperProtectionUnlockHash");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, hashInfo, sizeof(hashBuffer), &resultLength);
    if (!NT_SUCCESS(status) || hashInfo->Type != REG_BINARY || hashInfo->DataLength != KINNECTOR_SHA256_HASH_LENGTH) {
        // No expected hash configured - fail closed, same as an empty
        // allowlist elsewhere in this driver never meaning "allow
        // everything."
        ZwClose(keyHandle);
        return FALSE;
    }

    {
        // REG_SZ DataLength conventionally includes the trailing null -
        // trim it the same defensive way this driver's other REG_SZ reads
        // already do (see kinnector_filter.c's KinnectorLoadTestConfiguration),
        // only if it's actually present.
        USHORT dataLength = (USHORT)attemptInfo->DataLength;
        PWCH chars = (PWCH)attemptInfo->Data;

        if (dataLength >= sizeof(WCHAR) && chars[dataLength / sizeof(WCHAR) - 1] == L'\0') {
            dataLength -= sizeof(WCHAR);
        }

        status = KinnectorComputeSha256((PUCHAR)chars, dataLength, computedHash);
    }

    if (NT_SUCCESS(status)) {
        matched = RtlEqualMemory(computedHash, hashInfo->Data, KINNECTOR_SHA256_HASH_LENGTH);
    }

    // Never leave the plaintext attempt or the computed hash sitting in
    // stack memory longer than needed.
    RtlSecureZeroMemory(computedHash, sizeof(computedHash));
    RtlSecureZeroMemory(attemptBuffer, sizeof(attemptBuffer));

    ZwClose(keyHandle);
    return matched;
}
