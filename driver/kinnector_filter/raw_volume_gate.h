#pragma once

// Phase 7 step 9 (WINDOWS_COVERAGE_PLAN.md): "Raw-volume/physical-disk
// (\\.\C:, \\.\PhysicalDriveN) coarse allowlist gate - fold into this same
// driver rather than a separate project."
//
// This module covers only the \\.\C: (raw-volume) half of that line item.
// \\.\PhysicalDriveN opens never reach this driver at all - minifilters
// only attach to file-system volume instances (see kinnector_filter.c's
// InstanceSetupCallback, which already refuses everything except local NTFS
// disk volumes), never the underlying disk-class device stack a physical
// drive handle opens against. Gating \\.\PhysicalDriveN needs a wholly
// different attachment mechanism (a device-stack filter on the disk class,
// e.g. an upper filter via the Disk class GUID or a legacy AddDevice path) -
// categorically higher blast radius than anything this driver does today,
// since a bug there risks the boot/storage stack itself, not just a single
// file-system volume. Deliberately NOT attempted in this pass - flag as a
// separate, harder sub-step (9b) needing its own toolchain-proof-first
// increment (mirroring step 1's approach to the minifilter mechanism)
// before any real logic touches it.
//
// The allowlist here is coarse by design, same caveat class as this file's
// own name: KinnectorGetCurrentProcessShortImageName resolves via
// PsGetProcessImageFileName, which returns only the trailing ~15-character
// image file name with no path and no signer/hash verification (unlike
// Phase 5's ResolveCanonicalResourceIdentity/authenticode work in
// core/src/windows). A process can trivially spoof this by naming itself
// to match an allowlisted entry. This is intentionally the same tradeoff
// core/CLAUDE.md's "Known debt" section already documents for
// kinnector.bpf.c's TREE_TRUSTED_ADMIN allowlist on Linux - a coarse
// name-based gate is what "coarse allowlist gate" in the plan text actually
// means, not a placeholder for something stronger left unfinished. Do not
// silently upgrade this to imply signer-based verification without an
// explicit, separately-flagged change.
//
// No dynamic allocation on the hot path, same discipline as
// protected_resources.h - fixed-capacity array guarded by a spin lock.

#include <ntddk.h>

#define KINNECTOR_MAX_RAW_VOLUME_ALLOWLIST 32

// PsGetProcessImageFileName's underlying EPROCESS field is a fixed 16-byte
// ANSI buffer (15 chars + null) - this bound is not a stylistic choice,
// it's the real width of what that API can ever return.
#define KINNECTOR_IMAGE_NAME_MAX_CHARS 16

VOID
KinnectorRawVolumeGateInit(
    VOID
    );

// ImageFileName must be a null-terminated ANSI string. Returns FALSE only
// if the table is full - same "unprotectable resource just stays
// unprotected" discipline as KinnectorAddProtectedResource; never treat a
// failed add as a reason to start denying.
BOOLEAN
KinnectorAddRawVolumeAllowlistEntry(
    _In_ PCCH ImageFileName
    );

// Empty allowlist (the default, no test seed present) means "nothing to
// match" - callers must treat that as fail-open (never deny), same as an
// empty protected-resource/registry-key list elsewhere in this driver.
BOOLEAN
KinnectorRawVolumeAllowlistIsEmpty(
    VOID
    );

BOOLEAN
KinnectorIsRawVolumeAllowlisted(
    _In_ PCCH ImageFileName
    );

VOID
KinnectorRawVolumeGateClear(
    VOID
    );
