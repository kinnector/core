#pragma once

// Phase 7 step 10 addendum (this change): password-gated override for
// gTamperProtectionEnabled. Directly answers the real problem step 10's
// tamper-protection half has on its own: once gTamperProtectionEnabled is
// on, a plain sc stop/fltmc unload is refused, and there is no documented
// way to force a MANDATORY unload on demand - only a real system shutdown
// or forced volume dismount ever sets that flag. Without an escape hatch,
// the only way to turn tamper-protection back off would be a reboot. This
// gives whoever knows the configured password a way to authorize one
// specific unload attempt, without making gTamperProtectionEnabled itself
// writable by anyone who can reach the registry - that would just move the
// problem, since anyone able to flip it off to test could flip it off to
// attack the driver too.
//
// SECURITY-HONEST CAVEAT, read before treating this as production-grade:
// the expected password hash is read from this driver's own \Parameters
// registry key, which (in this project's current dev/test-scaffolding
// form) is NOT ACL-hardened - deliberately, since every other test-only
// seed this driver reads (see kinnector_filter.c's KinnectorLoadTestConfiguration)
// depends on \Parameters staying writable by a plain elevated session, the
// same workflow this whole phase has used throughout. That means, TODAY, a
// local admin who can write to \Parameters could overwrite the stored hash
// with one they control and grant themselves an unlock - this mechanism
// currently proves "the caller knows the configured password," not "cannot
// be defeated by a local admin." Closing that gap needs this specific
// value (or the whole key) locked to SYSTEM-only write, which isn't done
// here because it would break every other registry-seeded test flag this
// driver currently relies on. State this plainly rather than imply more
// security than what's actually here - same discipline as every other
// caveat in this driver (raw_volume_gate.h's coarse-allowlist note, the
// PPL caveat in kinnector_filter.c, etc.).

#include <ntddk.h>

#define KINNECTOR_SHA256_HASH_LENGTH 32

// Reads TamperProtectionUnlockAttempt (REG_SZ) from ParametersKeyPath,
// clears it immediately after reading (a password attempt must never
// linger in the registry past the single check it's for, whether or not it
// matches), hashes it with SHA-256 (kernel CNG - see tamper_unlock.c), and
// compares against TamperProtectionUnlockHash (REG_BINARY, 32 bytes,
// pre-configured separately - see driver/set_tamper_unlock_password.ps1).
// Returns TRUE only on an exact 32-byte match. Fails closed on every error
// path (key/value missing, wrong type/length, hashing failure) - the
// tamper-protection refusal stays in effect unless this affirmatively
// proves a match, same "empty/missing config never means allow" discipline
// as every other gate in this driver.
BOOLEAN
KinnectorCheckTamperUnlockPassword(
    _In_ PUNICODE_STRING ParametersKeyPath
    );
