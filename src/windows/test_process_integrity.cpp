#include "process_integrity.h"
#include "resource_identity.h"
#include "authenticode.h"
#include <windows.h>
#include <iostream>

using kinnector::windows::GetAuthenticodeSigner;
using kinnector::windows::IsAuthorizedSelfUpdate;
using kinnector::windows::ProcessIntegrityStore;
using kinnector::windows::ProtectedResourceStore;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            return 1; \
        } \
    } while (0)

int main() {
    std::cout << "=== Running Windows Process Integrity + Self-Update Authorization Test ===" << std::endl;

    ProcessIntegrityStore integrity;
    const uint32_t pid = 4242;
    const uint64_t create_time = 133700000000000000ULL;  // arbitrary stand-in FILETIME value

    std::cout << "[Test] An untracked (pid, create_time) defaults to clear (documented no-op-until-Phase-4 behavior)..." << std::endl;
    CHECK(integrity.IsProcessClear(pid, create_time), "untracked process reads as clear by default");

    std::cout << "[Test] Flagging the process as injected..." << std::endl;
    CHECK(integrity.FlagProcessInjected(pid, create_time), "FlagProcessInjected succeeded");
    CHECK(!integrity.IsProcessClear(pid, create_time), "flagged process is no longer clear");

    // A different create_time for the same pid (simulating PID reuse by an
    // unrelated later process) must NOT inherit the flag - this is the
    // actual point of the composite key.
    CHECK(integrity.IsProcessClear(pid, create_time + 1), "a different process instance reusing the same pid is unaffected");

    std::cout << "[Test] Clearing the flag..." << std::endl;
    CHECK(integrity.ClearProcessFlag(pid, create_time), "ClearProcessFlag succeeded");
    CHECK(integrity.IsProcessClear(pid, create_time), "process is clear again after ClearProcessFlag");

    std::cout << "[Test] Exercising the combined self-update gate (signed AND clear)..." << std::endl;
    const std::wstring signed_binary = L"C:\\Windows\\explorer.exe";  // embedded-signed, see authenticode.h's catalog-signing caveat
    auto signer = GetAuthenticodeSigner(signed_binary);
    CHECK(signer.has_value(), "signed_binary resolves a valid Authenticode signer");

    ProtectedResourceStore resources;
    const uint32_t volume_serial = 111;
    const uint64_t frn = 222;
    resources.AddProtectedResource(volume_serial, frn, /*category=*/1);
    resources.AddResourceOwnerSigner(volume_serial, frn, *signer);

    CHECK(IsAuthorizedSelfUpdate(resources, integrity, volume_serial, frn, signed_binary, pid, create_time),
          "signed + clear process IS authorized to self-update");

    integrity.FlagProcessInjected(pid, create_time);
    CHECK(!IsAuthorizedSelfUpdate(resources, integrity, volume_serial, frn, signed_binary, pid, create_time),
          "signed but INJECTED process is NOT authorized, even though the binary itself is still validly signed - "
          "this is the actual point of the combined gate over a signer-only check");
    integrity.ClearProcessFlag(pid, create_time);

    // Unsigned binary must fail even when the process is clear.
    const std::wstring unsigned_stand_in = L"C:\\Windows\\System32\\notepad.exe";  // catalog-signed, not embedded - see authenticode.h
    CHECK(!IsAuthorizedSelfUpdate(resources, integrity, volume_serial, frn, unsigned_stand_in, pid, create_time),
          "unsigned (from this check's perspective) binary is NOT authorized even though the process is clear");

    std::cout << "\n>>> TEST SUCCESSFUL! Process integrity store and combined self-update gate validated. <<<" << std::endl;
    return 0;
}
