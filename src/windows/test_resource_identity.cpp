#include "resource_identity.h"
#include "authenticode.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

using kinnector::windows::CanonicalResourceIdentity;
using kinnector::windows::GetAuthenticodeSigner;
using kinnector::windows::ProtectedResourceStore;
using kinnector::windows::ResolveCanonicalResourceIdentity;

// This project builds Release/-DNDEBUG (see core/CLAUDE.md) - assert() is
// elided, so every check here is a real if/return, not assert().
#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            return 1; \
        } \
    } while (0)

int main() {
    std::cout << "=== Running Windows Canonical Resource Identity Test ===" << std::endl;

    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    DWORD pid = GetCurrentProcessId();
    std::wstring original = std::wstring(temp_dir) + L"kinnector_test_resource_identity_" + std::to_wstring(pid) + L".txt";
    std::wstring hardlink = std::wstring(temp_dir) + L"kinnector_test_resource_identity_" + std::to_wstring(pid) + L"_link.txt";
    std::wstring unrelated = std::wstring(temp_dir) + L"kinnector_test_resource_identity_" + std::to_wstring(pid) + L"_unrelated.txt";

    DeleteFileW(original.c_str());
    DeleteFileW(hardlink.c_str());
    DeleteFileW(unrelated.c_str());

    {
        std::ofstream ofs(original, std::ios::binary);
        ofs << "kinnector resource identity test payload";
    }
    {
        std::ofstream ofs(unrelated, std::ios::binary);
        ofs << "a different file entirely";
    }

    std::cout << "[Test] Resolving identity of the original file..." << std::endl;
    CanonicalResourceIdentity original_id = ResolveCanonicalResourceIdentity(original);
    CHECK(original_id.valid, "original file's identity resolved");
    std::cout << "[Test] original: volume_serial=" << original_id.volume_serial
              << " frn=" << original_id.file_reference_number << std::endl;

    std::cout << "[Test] Creating hardlink and resolving its identity..." << std::endl;
    CHECK(CreateHardLinkW(hardlink.c_str(), original.c_str(), nullptr), "CreateHardLinkW succeeded");
    CanonicalResourceIdentity hardlink_id = ResolveCanonicalResourceIdentity(hardlink);
    CHECK(hardlink_id.valid, "hardlink's identity resolved");
    std::cout << "[Test] hardlink: volume_serial=" << hardlink_id.volume_serial
              << " frn=" << hardlink_id.file_reference_number << std::endl;

    CHECK(hardlink_id.volume_serial == original_id.volume_serial &&
              hardlink_id.file_reference_number == original_id.file_reference_number,
          "hardlink resolves to the SAME canonical identity as the original - "
          "this is the direct proof the path-aliasing gap is closed");

    std::cout << "[Test] Resolving identity of an unrelated file..." << std::endl;
    CanonicalResourceIdentity unrelated_id = ResolveCanonicalResourceIdentity(unrelated);
    CHECK(unrelated_id.valid, "unrelated file's identity resolved");
    CHECK(!(unrelated_id.volume_serial == original_id.volume_serial &&
            unrelated_id.file_reference_number == original_id.file_reference_number),
          "an unrelated file resolves to a DIFFERENT canonical identity");

    std::cout << "[Test] Resolving identity of a nonexistent path..." << std::endl;
    CanonicalResourceIdentity missing_id = ResolveCanonicalResourceIdentity(
        std::wstring(temp_dir) + L"kinnector_test_resource_identity_does_not_exist.txt");
    CHECK(!missing_id.valid, "a nonexistent path resolves as invalid, not a crash or garbage identity");

    std::cout << "[Test] Exercising ProtectedResourceStore add/lookup/remove..." << std::endl;
    ProtectedResourceStore store;
    CHECK(store.Count() == 0, "store starts empty");
    CHECK(store.AddProtectedResource(original_id.volume_serial, original_id.file_reference_number, /*category=*/7),
          "AddProtectedResource succeeded");
    CHECK(store.Count() == 1, "store has one entry after add");

    uint32_t looked_up_category = 0;
    CHECK(store.LookupProtectedResource(original_id.volume_serial, original_id.file_reference_number, &looked_up_category),
          "LookupProtectedResource found the entry");
    CHECK(looked_up_category == 7, "looked-up category matches what was stored");

    // The hardlink shares the original's canonical identity, so a lookup
    // keyed on the hardlink's own resolved identity must also hit - this is
    // the actual point of keying the store on canonical identity rather than
    // path: whichever name protects the file, both names are covered.
    CHECK(store.LookupProtectedResource(hardlink_id.volume_serial, hardlink_id.file_reference_number, nullptr),
          "lookup via the hardlink's identity also hits the same entry");

    CHECK(!store.LookupProtectedResource(unrelated_id.volume_serial, unrelated_id.file_reference_number, nullptr),
          "the unrelated file's identity does NOT hit");

    CHECK(store.RemoveProtectedResource(original_id.volume_serial, original_id.file_reference_number),
          "RemoveProtectedResource succeeded");
    CHECK(store.Count() == 0, "store is empty again after remove");
    CHECK(!store.LookupProtectedResource(original_id.volume_serial, original_id.file_reference_number, nullptr),
          "lookup after remove no longer hits");

    std::cout << "[Test] Exercising owner-signer allowlist (vendor-updater authorization)..." << std::endl;
    // Stand-in for "a vendor's auto-updater binary" - any real, embedded-Authenticode-
    // signed binary works here, since the point being tested is signer-identity
    // matching, not anything explorer-specific. explorer.exe specifically (not e.g.
    // notepad.exe, which is catalog-signed, not embedded - WinVerifyTrust's plain
    // WTD_CHOICE_FILE path here only checks embedded signatures, see authenticode.h)
    // because it's guaranteed present on every Windows install, unlike third-party
    // binaries this test can't assume are installed.
    const std::wstring signed_system_binary = L"C:\\Windows\\explorer.exe";
    auto system_signer = GetAuthenticodeSigner(signed_system_binary);
    CHECK(system_signer.has_value(), "a real Windows system binary resolves a valid Authenticode signer");
    std::cout << "[Test] resolved signer: " << *system_signer << std::endl;

    ProtectedResourceStore signer_store;
    CHECK(!signer_store.IsAuthorizedSigner(original_id.volume_serial, original_id.file_reference_number, *system_signer),
          "signer is NOT authorized before being added to the owner set");
    CHECK(signer_store.AddResourceOwnerSigner(original_id.volume_serial, original_id.file_reference_number, *system_signer),
          "AddResourceOwnerSigner succeeded");
    CHECK(signer_store.IsAuthorizedSigner(original_id.volume_serial, original_id.file_reference_number, *system_signer),
          "signer IS authorized after being added to the owner set");

    // The actual point: check by live-resolving a real binary's signer, not
    // just by matching an already-known string - this is what a future
    // write-time hook would call against the process that's actually asking.
    CHECK(signer_store.IsAuthorizedModifyingPath(original_id.volume_serial, original_id.file_reference_number, signed_system_binary),
          "IsAuthorizedModifyingPath authorizes the signed system binary");

    // Our own unsigned test payload file must NOT be treated as an authorized
    // modifier, even against the same protected resource - unsigned is never
    // authorized regardless of what's in the owner set.
    CHECK(!signer_store.IsAuthorizedModifyingPath(original_id.volume_serial, original_id.file_reference_number, unrelated),
          "IsAuthorizedModifyingPath rejects an unsigned binary");

    CHECK(signer_store.RemoveResourceOwnerSigner(original_id.volume_serial, original_id.file_reference_number, *system_signer),
          "RemoveResourceOwnerSigner succeeded");
    CHECK(!signer_store.IsAuthorizedSigner(original_id.volume_serial, original_id.file_reference_number, *system_signer),
          "signer is no longer authorized after removal");

    DeleteFileW(original.c_str());
    DeleteFileW(hardlink.c_str());
    DeleteFileW(unrelated.c_str());

    std::cout << "\n>>> TEST SUCCESSFUL! Canonical resource identity resolution, protected-resource store, "
                 "and owner-signer allowlist all validated. <<<" << std::endl;
    return 0;
}
