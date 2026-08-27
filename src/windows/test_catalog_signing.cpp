// WS3 (MVP_REACTIVE_PLAN.md) - catalog-signing fallback in authenticode.cpp.
//
// Before WS3, VerifyAuthenticodeSignature only checked embedded Authenticode
// signatures, so catalog-signed system/MSI binaries (a real fraction of
// Windows) resolved as "unsigned" - which would make a legitimately-signed
// vendor updater look like an unauthorized modifier. This proves:
//   1. an embedded-signed binary still verifies (no regression),
//   2. a catalog-signed system binary now verifies (the fix),
//   3. a tampered copy of a signed binary verifies as NEITHER,
//   4. an unsigned file resolves no signer.
//
// No elevation, no ETW - pure signature verification.

#include "authenticode.h"

#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>

using kinnector::windows::GetAuthenticodeSigner;
using kinnector::windows::VerifyAuthenticodeSignature;

#define CHECK(cond, msg)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" \
                      << std::endl;                                            \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static bool Contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

int main() {
    std::cout << "=== Running Windows Catalog-Signing Fallback (WS3) Test ===" << std::endl;

    wchar_t windir[MAX_PATH];
    GetWindowsDirectoryW(windir, MAX_PATH);
    const std::wstring win = windir;

    // ── 1: embedded-signed still verifies ──────────────────────────────────
    const std::wstring explorer = win + L"\\explorer.exe";
    auto explorer_signer = GetAuthenticodeSigner(explorer);
    CHECK(explorer_signer.has_value(), "embedded-signed explorer.exe still verifies");
    std::cout << "[Test] explorer.exe signer: " << *explorer_signer << std::endl;
    CHECK(Contains(*explorer_signer, "Microsoft"), "explorer.exe signer is Microsoft");

    // ── 2: catalog-signed system binary now verifies ──────────────────────
    // notepad.exe is catalog-signed, not embedded (see the pre-WS3 comment in
    // authenticode.h) - it used to return TRUST_E_NOSIGNATURE here.
    const wchar_t* candidates[] = { L"\\System32\\notepad.exe",
                                    L"\\System32\\where.exe",
                                    L"\\System32\\tasklist.exe",
                                    L"\\System32\\ipconfig.exe" };
    bool any_catalog = false;
    for (const wchar_t* rel : candidates) {
        const std::wstring p = win + rel;
        if (GetFileAttributesW(p.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        auto signer = GetAuthenticodeSigner(p);
        if (signer.has_value()) {
            std::wcout << L"[Test] catalog-class binary verified: " << p << std::endl;
            std::cout << "[Test]   signer: " << *signer << std::endl;
            CHECK(Contains(*signer, "Microsoft"), "catalog signer is Microsoft");
            any_catalog = true;
            break;
        }
    }
    CHECK(any_catalog,
          "at least one catalog-signed system binary now resolves a signer "
          "(the WS3 fix - these returned TRUST_E_NOSIGNATURE before)");

    // ── 3: tampered copy verifies as neither embedded nor catalog ─────────
    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    const std::wstring tampered =
        std::wstring(temp_dir) + L"kinnector_ws3_tampered_" +
        std::to_wstring(GetCurrentProcessId()) + L".exe";
    const std::wstring unsigned_file =
        std::wstring(temp_dir) + L"kinnector_ws3_unsigned_" +
        std::to_wstring(GetCurrentProcessId()) + L".bin";
    DeleteFileW(tampered.c_str());
    DeleteFileW(unsigned_file.c_str());

    CHECK(CopyFileW(explorer.c_str(), tampered.c_str(), FALSE), "copied explorer.exe");
    {
        // Flip a byte well inside the file - breaks both the embedded PE hash
        // and any catalog membership hash.
        std::fstream f(tampered, std::ios::in | std::ios::out | std::ios::binary);
        CHECK(f.is_open(), "opened tampered copy for patching");
        f.seekp(4096);
        char c = 0;
        f.read(&c, 1);
        f.seekp(4096);
        c = static_cast<char>(c ^ 0xFF);
        f.write(&c, 1);
    }
    CHECK(!GetAuthenticodeSigner(tampered).has_value(),
          "a tampered copy of a signed binary verifies as NEITHER embedded nor catalog");

    // ── 4: unsigned file resolves nothing ────────────────────────────────
    {
        std::ofstream f(unsigned_file, std::ios::binary);
        f << "not a signed binary";
    }
    char buf[256] = {};
    CHECK(!VerifyAuthenticodeSignature(unsigned_file, buf, sizeof(buf)),
          "a plain unsigned file does not verify");
    CHECK(buf[0] == '\0', "no signer string written for an unsigned file");

    DeleteFileW(tampered.c_str());
    DeleteFileW(unsigned_file.c_str());

    std::cout << "\n>>> TEST SUCCESSFUL! Catalog-signing fallback validated. <<<" << std::endl;
    return 0;
}
