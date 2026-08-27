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
// As of MVP_REACTIVE_PLAN.md WS3 this checks an embedded Authenticode signature
// first (WTD_CHOICE_FILE) and, only when there is NO embedded signature
// (TRUST_E_NOSIGNATURE), falls back to Windows' catalog-signing mechanism
// (CryptCATAdmin* + WTD_CHOICE_CATALOG). So catalog-signed system/MSI binaries
// like C:\Windows\System32\notepad.exe now resolve a signer instead of
// TRUST_E_NOSIGNATURE. A present-but-invalid embedded signature (revoked,
// tampered, untrusted root) is still a hard failure - the catalog path is not
// tried in that case.
bool VerifyAuthenticodeSignature(const std::wstring& path, char* out_signer, size_t max_len);

// Thread-safe, process-wide cached wrapper around VerifyAuthenticodeSignature
// (MVP_REACTIVE_PLAN.md WS6). Keyed on (resolved path, file size,
// last-write-time), so a replaced binary is re-verified rather than trusted
// from a stale entry. Accepts NT device paths (\Device\HarddiskVolumeN\...)
// and normalizes them internally.
//
// The FIRST verification of a given file version still runs WinVerifyTrust
// inline on the calling thread, and it opens the file to key the cache on
// (size, last-write-time) - so this is NOT safe for the ETW callback thread.
// Use it from workers/tests. The callback thread uses PeekSignerCache below.
bool CachedVerifyAuthenticodeSignature(const std::wstring& path, char* out_signer, size_t max_len);

// Zero-I/O cache peek for the ETW callback thread (MVP_REACTIVE_PLAN.md WS6):
// pure lock + map lookup keyed on the normalised path string alone (no file
// open, no size/last-write check). Returns false on a miss - the caller should
// emit "unknown" and schedule an async warm (WarmSignerCache) so the next hit
// is served from cache. `raw_path` may be an NT device path.
bool PeekSignerCache(const std::wstring& raw_path, bool* out_signed,
                     char* out_signer, size_t max_len);

// Populate the cache for `raw_path` (runs WinVerifyTrust + a file open).
// Call only from a worker thread. Idempotent / cheap once warm.
void WarmSignerCache(const std::wstring& raw_path);

// Convenience wrapper: nullopt if unsigned/untrusted, else the leaf signer's
// display-name subject - the same string antitheft.md §4 calls the
// Windows-side identity_pin for an owner-allowlist entry.
std::optional<std::string> GetAuthenticodeSigner(const std::wstring& path);

} // namespace kinnector::windows
