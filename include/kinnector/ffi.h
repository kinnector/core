#ifndef KINNECTOR_FFI_H
#define KINNECTOR_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include "kinnector/telemetry.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  ifdef kinnector_core_EXPORTS
#    define KINNECTOR_API __declspec(dllexport)
#  else
#    define KINNECTOR_API __declspec(dllimport)
#  endif
#else
#  define KINNECTOR_API
#endif

// Initialize the telemetry engine configuration
KINNECTOR_API bool initialize_telemetry_engine(const char* bpf_obj_path, const char* socket_path, const char* auth_token);

// Start the telemetry engine (loading eBPF/LSM programs and starting IPC connection)
KINNECTOR_API bool start_telemetry_engine();

// Stop the telemetry engine (unloading hooks and disconnecting IPC)
KINNECTOR_API void stop_telemetry_engine();

// Populate sensitive inode category mappings. Phase 6 (LINUX_COVERAGE_PLAN.md):
// `dev` (st_dev/dev_t, widened) makes the identity canonical across
// bind-mounts/multiple filesystems with overlapping inode ranges — a bare
// inode number alone is ambiguous. See kinnector.bpf.c's resource_id
// declaration comment for which maps this applies to and why.
KINNECTOR_API bool add_sensitive_inode(uint64_t dev, uint64_t inode, uint32_t category);
KINNECTOR_API bool add_protected_static_inode(uint64_t dev, uint64_t inode);
KINNECTOR_API bool remove_protected_static_inode(uint64_t dev, uint64_t inode);

// Register a directory inode as a DB data-dir bypass (suppresses telemetry for DB processes)
KINNECTOR_API bool add_bypassed_directory_inode(uint64_t dev, uint64_t inode);

// Remove a directory inode from the DB bypass map (called on DB process stop / upgrade)
KINNECTOR_API bool remove_bypassed_directory_inode(uint64_t dev, uint64_t inode);

// Phase 3 (LINUX_COVERAGE_PLAN.md): register/unregister a legitimate owner process
// (identified by its executable's bare inode — Phase 6's dev+inode compositing
// applies to the protected *resource* side only, not this lossy owner-hash
// bucket input) for a protected resource identified by (resource_dev,
// resource_inode). Antitheft-only — the kernel side only ever consults this
// once CONFIG_DEPLOYMENT_MODE == MODE_ANTITHEFT has been set via set_config_value.
KINNECTOR_API bool add_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);
KINNECTOR_API bool remove_resource_owner(uint64_t resource_dev, uint64_t resource_inode, uint64_t owner_exec_inode);

// Populate trusted executable inodes mappings
KINNECTOR_API bool add_trusted_exec_inode(uint64_t inode, uint32_t trust_level);
KINNECTOR_API bool is_trusted_exec_inode(uint64_t inode);

// Set configuration variables (e.g. blocking mode enabled)
KINNECTOR_API bool set_config_value(uint32_t index, uint32_t value);

// Update process threshold dynamically (1 = Untrusted, 2 = Verified, 3 = Naked TTY)
KINNECTOR_API bool update_process_threshold(uint32_t pid, uint64_t start_time, uint32_t threshold);

// Update/Delete BPF map entries dynamically from userspace
KINNECTOR_API bool update_map_entry(int map_type, uint32_t pid, uint64_t start_time, uint32_t value);
KINNECTOR_API bool delete_map_entry(int map_type, uint32_t pid, uint64_t start_time);

// Send a telemetry event through the active IPC sender (for verification/testing)
KINNECTOR_API bool send_telemetry_event(const TelemetryEvent* event);

// Check if LSM mode is actively loaded in the kernel
KINNECTOR_API bool is_lsm_active();

// Firewall (warden/src/firewall) — see ebpf_loader.h's AddFirewallCidr doc
// comment for the addr/prefixlen contract.
KINNECTOR_API bool add_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen,
                                      uint32_t rule_id, uint16_t port, uint8_t proto,
                                      uint8_t direction, uint8_t action);
KINNECTOR_API bool remove_firewall_cidr(bool is_v6, const uint8_t* addr, uint32_t prefixlen);
KINNECTOR_API int64_t count_firewall_entries();

// Windows-only: register/remove/query a protected-resource identity, keyed
// on the canonical (volume_serial, file_reference_number) pair from
// resource_identity.h - not raw dev/inode, Windows has no equivalent.
// Populated by the calling agent (antitheftd) after it loads/diffs
// protect-community/configs/antitheft/ itself; core never touches that
// config, same boundary the Linux setters above use for kinnector-config.
// See WINDOWS_COVERAGE_PLAN.md Phase 5. No-op (returns false) on
// non-Windows builds.
KINNECTOR_API bool add_protected_resource_windows(uint32_t volume_serial, uint64_t file_reference_number, uint32_t category);
KINNECTOR_API bool remove_protected_resource_windows(uint32_t volume_serial, uint64_t file_reference_number);
KINNECTOR_API bool is_protected_resource_windows(uint32_t volume_serial, uint64_t file_reference_number, uint32_t* out_category);

// Windows-only: owner-allowlist entries for a protected resource, keyed on
// an Authenticode leaf-signer display-name subject (antitheft.md §4's
// identity_pin) rather than a specific binary path/hash - this is what lets
// a vendor's auto-updater keep working across binary-content-changing
// updates: any binary signed by an allowlisted vendor is authorized,
// not one pinned image. signer_subject is a UTF-8 C string, matching what
// TelemetryEvent::ImageLoadDetails::signer_subject already carries.
KINNECTOR_API bool add_resource_owner_signer_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* signer_subject);
KINNECTOR_API bool remove_resource_owner_signer_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* signer_subject);
KINNECTOR_API bool is_authorized_signer_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* signer_subject);

// Convenience: resolves modifying_binary_path's own live Authenticode
// signer and checks it against the resource's owner set in one call.
// modifying_binary_path is UTF-8. Returns false if the binary is
// unsigned/untrusted, same as any signer not in the allowlist.
KINNECTOR_API bool is_authorized_modifying_path_windows(uint32_t volume_serial, uint64_t file_reference_number, const char* modifying_binary_path);

// Windows-only: process-integrity flags for the self-update trust gate
// (antitheft.md §3 - trust is a continuously-revocable property of a
// specific running process instance, not a one-time open-time decision).
// Composite-keyed on (pid, create_time) - NEVER pid alone, Windows reuses
// PIDs aggressively; create_time is the process's own creation timestamp
// (e.g. GetProcessTimes' lpCreationTime as a 64-bit FILETIME value).
// CURRENTLY A NO-OP PASS-THROUGH: nothing calls flag_process_injected_windows
// yet, since Phase 4's ETW-TI injection detection is blocked pending real
// Antimalware-PPL/ELAM certification - is_process_clear_windows always
// returns true today. See WINDOWS_COVERAGE_PLAN.md / process_integrity.h.
KINNECTOR_API bool flag_process_injected_windows(uint32_t pid, uint64_t create_time);
KINNECTOR_API bool clear_process_flag_windows(uint32_t pid, uint64_t create_time);
KINNECTOR_API bool is_process_clear_windows(uint32_t pid, uint64_t create_time);

// The actual self-update authorization gate: BOTH signed by an allowlisted
// vendor AND the modifying process instance is currently clear of
// injection indicators - being signed alone is not sufficient, a
// legitimately-signed updater binary can still be a hijacked process
// instance. modifying_binary_path is UTF-8. Inherits the integrity check's
// current no-op caveat above.
KINNECTOR_API bool is_authorized_self_update_windows(uint32_t volume_serial, uint64_t file_reference_number,
                                                      const char* modifying_binary_path,
                                                      uint32_t modifying_pid, uint64_t modifying_process_create_time);

#ifdef __cplusplus
}
#endif

#endif // KINNECTOR_FFI_H
