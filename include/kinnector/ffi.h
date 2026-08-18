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

// Populate sensitive inode category mappings
KINNECTOR_API bool add_sensitive_inode(uint64_t inode, uint32_t category);
KINNECTOR_API bool add_protected_static_inode(uint64_t inode);
KINNECTOR_API bool remove_protected_static_inode(uint64_t inode);

// Register a directory inode as a DB data-dir bypass (suppresses telemetry for DB processes)
KINNECTOR_API bool add_bypassed_directory_inode(uint64_t inode);

// Remove a directory inode from the DB bypass map (called on DB process stop / upgrade)
KINNECTOR_API bool remove_bypassed_directory_inode(uint64_t inode);

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

#ifdef __cplusplus
}
#endif

#endif // KINNECTOR_FFI_H
