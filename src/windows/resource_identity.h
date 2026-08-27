#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace kinnector::windows {

// Volume serial number (GetFileInformationByHandle's dwVolumeSerialNumber)
// plus the classic 64-bit NTFS File Reference Number (nFileIndexHigh/Low
// combined) - the pair a hardlink or NTFS junction to the same underlying
// file always resolves to, unlike the path string itself. Closes the
// Windows path-aliasing gap in antitheft.md §3 / WINDOWS_COVERAGE_PLAN.md
// Phase 5.
struct CanonicalResourceIdentity {
    uint32_t volume_serial = 0;
    uint64_t file_reference_number = 0;
    bool valid = false;
};

// Resolves a path to its canonical identity by opening it (read-attributes
// only, share-everything, FILE_FLAG_BACKUP_SEMANTICS so directories open
// too) and reading back GetFileInformationByHandle. Returns .valid = false
// on any failure (doesn't exist, access denied, etc.) rather than throwing.
CanonicalResourceIdentity ResolveCanonicalResourceIdentity(const std::wstring& path);

// In-memory store of protected-resource identities. Populated over FFI
// (add_protected_resource_windows in ffi.cpp) by the calling agent
// (antitheftd) after it loads/diffs protect-community/configs/antitheft/
// via kinnector-config itself - core never links or parses that config,
// same boundary Warden's add_sensitive_inode/add_firewall_cidr already use.
// Detection-only for now: nothing in core enforces against a lookup here
// until Phase 7's kernel driver exists.
class ProtectedResourceStore {
public:
    bool AddProtectedResource(uint32_t volume_serial, uint64_t file_reference_number, uint32_t category);
    bool RemoveProtectedResource(uint32_t volume_serial, uint64_t file_reference_number);
    bool LookupProtectedResource(uint32_t volume_serial, uint64_t file_reference_number, uint32_t* out_category) const;
    size_t Count() const;

    // Owner-allowlist entries (antitheft.md §4's "owner set"), Windows-side
    // identity_pin: an Authenticode leaf-signer display-name subject (see
    // authenticode.h's GetAuthenticodeSigner), NOT a specific binary
    // path/hash. This is what lets a vendor's auto-updater keep working
    // across binary-content-changing updates - the resource is authorized
    // for whichever specific binary is asking, as long as its signer
    // matches one of the entries registered here, not one specific image.
    // Decision is allowlist-only, per §4: not in the owner set -> denied,
    // no scoring. A signer entry can be added for a resource that hasn't
    // been added via AddProtectedResource yet (config load order isn't
    // guaranteed) - IsAuthorizedSigner still answers correctly either way,
    // it just won't have anything to match against until both exist.
    bool AddResourceOwnerSigner(uint32_t volume_serial, uint64_t file_reference_number, const std::string& signer_subject);
    bool RemoveResourceOwnerSigner(uint32_t volume_serial, uint64_t file_reference_number, const std::string& signer_subject);
    bool IsAuthorizedSigner(uint32_t volume_serial, uint64_t file_reference_number, const std::string& signer_subject) const;

    // Convenience: resolves modifying_binary_path's own live Authenticode
    // signer (authenticode.h) and checks it against the resource's owner
    // set in one call - what a future write-time enforcement hook (Phase 7)
    // or an interim detection hook would actually call. Returns false (not
    // authorized) if the binary is unsigned/untrusted, same as any signer
    // not in the allowlist.
    bool IsAuthorizedModifyingPath(uint32_t volume_serial, uint64_t file_reference_number,
                                    const std::wstring& modifying_binary_path) const;

private:
    struct Key {
        uint32_t volume_serial;
        uint64_t file_reference_number;
        bool operator==(const Key& other) const {
            return volume_serial == other.volume_serial &&
                   file_reference_number == other.file_reference_number;
        }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const {
            return std::hash<uint64_t>()((static_cast<uint64_t>(k.volume_serial) << 32) ^ k.file_reference_number);
        }
    };

    mutable std::mutex mutex_;
    std::unordered_map<Key, uint32_t, KeyHash> resources_;
    std::unordered_map<Key, std::unordered_set<std::string>, KeyHash> owner_signers_;
};

// ─────────────────────────────────────────────────────────────────────────────
// WS2 (MVP_REACTIVE_PLAN.md): protected registry keys.
//
// Registry has no File-Reference-Number equivalent - a key's identity is its
// path. CanonicalizeRegistryKey normalises the many forms a path arrives in:
//   \REGISTRY\MACHINE\...            native (ETW BaseObject chains, agent)
//   HKLM\... | HKEY_LOCAL_MACHINE\...          -> \REGISTRY\MACHINE\...
//   HKU\<SID>\... | HKEY_USERS\<SID>\...       -> \REGISTRY\USER\<SID>\...
//   HKCU\... | HKEY_CURRENT_USER\...           -> \REGISTRY\USER\<caller SID>\...
//   Software\...   (hive-relative, from an ETW chain that bottomed out)
// ...to: uppercased, '/'->'\', duplicate '\' collapsed, no trailing '\'.
//
// HKCU is resolved against the CALLING process token, which for a SYSTEM
// service is not the interactive user - the agent should register HKCU-scoped
// keys as HKU\<explicit SID>\... instead.
std::wstring CanonicalizeRegistryKey(const std::wstring& input);

class ProtectedRegistryStore {
public:
    // subtree=true also protects keys/values below `canonical_key`.
    bool AddProtectedKey(const std::wstring& canonical_key, uint32_t category, bool subtree);
    bool RemoveProtectedKey(const std::wstring& canonical_key);

    // `event_key` is canonicalised by the caller (or pass a raw form to the
    // FFI wrapper, which canonicalises). Matches when a registered key K:
    //   - equals event_key, or
    //   - K.subtree and event_key is a descendant of K, or
    //   - event_key ends with K on a path-component boundary - tolerates the
    //     case where an ETW BaseObject chain could not be resolved all the way
    //     to the hive root, so `event_key` is only hive-relative. For the
    //     protection use case (persistence keys, per-app credential keys) a
    //     hive-ambiguous match is a safe superset, not a false positive.
    bool LookupProtectedKey(const std::wstring& event_key, uint32_t* out_category) const;

    bool AddOwnerSigner(const std::wstring& canonical_key, const std::string& signer_subject);
    bool RemoveOwnerSigner(const std::wstring& canonical_key, const std::string& signer_subject);
    bool IsAuthorizedSigner(const std::wstring& event_key, const std::string& signer_subject) const;

    size_t Count() const;

private:
    struct Entry {
        uint32_t category = 0;
        bool subtree = false;
        std::unordered_set<std::string> owner_signers;
    };
    // Match `event_key` against the registered keys; returns the matching
    // registered key (canonical) or empty. Caller holds mutex_.
    std::wstring MatchLocked(const std::wstring& event_key) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::wstring, Entry> keys_;
};

} // namespace kinnector::windows
