#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace kinnector::windows {

// Real WinVerifyTrust Authenticode chain validation (WINTRUST_ACTION_GENERIC_VERIFY_V2).
// Returns whether the file has a valid, chain-verified signature; on success,
// writes the leaf signer's display-name subject into out_signer (matches the
// 256-byte convention of TelemetryEvent::ImageLoadDetails::signer_subject).
// Originally etw_consumer.cpp-local (Fix 4); extracted so the storage-ownership
// signer-allowlist check (resource_identity.h, WINDOWS_COVERAGE_PLAN.md Phase 5 /
// antitheft.md §4's identity_pin) can reuse it instead of re-implementing
// WinVerifyTrust plumbing a second time.
//
// KNOWN GAP (confirmed empirically 2026-08-26): WTD_CHOICE_FILE here only
// checks an *embedded* Authenticode signature. It does NOT fall back to
// Windows' separate catalog-signing mechanism (CryptCATAdmin*/WTD_CHOICE_CATALOG),
// which a real fraction of Windows system binaries use instead of an embedded
// signature - e.g. C:\Windows\System32\notepad.exe resolves TRUST_E_NOSIGNATURE
// (0x800B0100) here despite being a legitimately Microsoft-signed file, while
// C:\Windows\explorer.exe (embedded-signed) resolves successfully. Most
// standalone third-party installer/updater .exe files embed their signature
// directly (this is what the owner-signer allowlist in resource_identity.h
// is designed around), so this gap mainly affects OS system files and
// MSI-delivered binaries, not the general vendor-updater case - but callers
// checking a Windows system file specifically should not treat a false here
// as proof of tampering. Catalog fallback is real, scoped follow-up work
// (WINDOWS_COVERAGE_PLAN.md), not implemented yet - this also means the
// pre-existing image-load telemetry's is_signed field has the same gap.
bool VerifyAuthenticodeSignature(const std::wstring& path, char* out_signer, size_t max_len);

// Convenience wrapper: nullopt if unsigned/untrusted, else the leaf signer's
// display-name subject - the same string antitheft.md §4 calls the
// Windows-side identity_pin for an owner-allowlist entry.
std::optional<std::string> GetAuthenticodeSigner(const std::wstring& path);

} // namespace kinnector::windows
