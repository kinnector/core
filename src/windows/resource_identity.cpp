#include "resource_identity.h"
#include "authenticode.h"

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <vector>

#pragma comment(lib, "advapi32")

namespace kinnector::windows {

namespace {

std::wstring ToUpper(std::wstring s) {
    for (auto& c : s) c = towupper(c);
    return s;
}

// SID string of the process token, e.g. "S-1-5-21-...". Empty on failure.
std::wstring CallerSidString() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return L"";
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    std::wstring out;
    if (len && GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &s)) {
            out = s;
            LocalFree(s);
        }
    }
    CloseHandle(token);
    return out;
}

// uppercase, '/'->'\', collapse duplicate '\', strip trailing '\'.
std::wstring NormalizePath(std::wstring s) {
    for (auto& c : s) {
        if (c == L'/') c = L'\\';
        else c = towupper(c);
    }
    std::wstring out;
    out.reserve(s.size());
    bool prev_slash = false;
    for (wchar_t c : s) {
        if (c == L'\\') {
            if (prev_slash) continue;
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out += c;
    }
    while (!out.empty() && out.back() == L'\\') out.pop_back();
    return out;
}

std::vector<std::wstring> SplitComponents(const std::wstring& canonical) {
    std::vector<std::wstring> parts;
    size_t i = 0;
    while (i < canonical.size()) {
        if (canonical[i] == L'\\') { ++i; continue; }
        size_t j = canonical.find(L'\\', i);
        if (j == std::wstring::npos) j = canonical.size();
        parts.emplace_back(canonical.substr(i, j - i));
        i = j;
    }
    return parts;
}

// Drop a leading \REGISTRY\MACHINE or \REGISTRY\USER\<SID> so a hive-relative
// path and a fully-qualified one can be compared.
std::vector<std::wstring> StripHive(std::vector<std::wstring> c) {
    if (c.size() >= 2 && c[0] == L"REGISTRY" &&
        (c[1] == L"MACHINE" || c[1] == L"USER")) {
        size_t drop = 2;
        if (c[1] == L"USER" && c.size() >= 3 && c[2].rfind(L"S-1-", 0) == 0) drop = 3;
        c.erase(c.begin(), c.begin() + drop);
    }
    return c;
}

bool IsSuffix(const std::vector<std::wstring>& big, const std::vector<std::wstring>& small_) {
    if (small_.empty() || small_.size() > big.size()) return false;
    return std::equal(small_.rbegin(), small_.rend(), big.rbegin());
}

bool IsPrefix(const std::vector<std::wstring>& big, const std::vector<std::wstring>& small_) {
    if (small_.empty() || small_.size() > big.size()) return false;
    return std::equal(small_.begin(), small_.end(), big.begin());
}

} // namespace

std::wstring CanonicalizeRegistryKey(const std::wstring& input) {
    std::wstring s = input;
    for (auto& c : s) if (c == L'/') c = L'\\';

    size_t start = s.find_first_not_of(L'\\');
    if (start == std::wstring::npos) return L"";
    std::wstring body = s.substr(start);

    size_t slash = body.find(L'\\');
    std::wstring first = (slash == std::wstring::npos) ? body : body.substr(0, slash);
    std::wstring rest = (slash == std::wstring::npos) ? L"" : body.substr(slash);
    std::wstring uf = ToUpper(first);

    std::wstring prefix;
    if (uf == L"HKLM" || uf == L"HKEY_LOCAL_MACHINE") {
        prefix = L"\\REGISTRY\\MACHINE";
    } else if (uf == L"HKCR" || uf == L"HKEY_CLASSES_ROOT") {
        prefix = L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES";
    } else if (uf == L"HKU" || uf == L"HKEY_USERS") {
        prefix = L"\\REGISTRY\\USER";
    } else if (uf == L"HKCU" || uf == L"HKEY_CURRENT_USER") {
        std::wstring sid = CallerSidString();
        prefix = sid.empty() ? L"\\REGISTRY\\USER" : (L"\\REGISTRY\\USER\\" + sid);
    } else if (uf == L"REGISTRY") {
        return NormalizePath(L"\\" + body);
    } else {
        // Hive-relative (an ETW BaseObject chain that didn't reach the root),
        // or an unrecognised form - keep as-is, just normalised.
        return NormalizePath(body);
    }
    return NormalizePath(prefix + rest);
}

// ── ProtectedRegistryStore ──────────────────────────────────────────────────

bool ProtectedRegistryStore::AddProtectedKey(const std::wstring& canonical_key,
                                             uint32_t category, bool subtree) {
    if (canonical_key.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    auto& e = keys_[canonical_key];
    e.category = category;
    e.subtree = subtree;
    return true;
}

bool ProtectedRegistryStore::RemoveProtectedKey(const std::wstring& canonical_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    return keys_.erase(canonical_key) > 0;
}

std::wstring ProtectedRegistryStore::MatchLocked(const std::wstring& event_key) const {
    if (event_key.empty()) return L"";
    const auto ec = SplitComponents(event_key);
    const auto ec_nohive = StripHive(ec);

    std::wstring suffix_hit;  // weaker match, used only if no stronger one found
    for (const auto& [k, entry] : keys_) {
        const auto kc = SplitComponents(k);
        if (kc == ec) return k;  // exact

        if (entry.subtree) {
            if (IsPrefix(ec, kc)) return k;
            if (IsPrefix(StripHive(ec), StripHive(kc))) return k;
        }
        // Hive-ambiguity tolerance: the shorter component list is a suffix of
        // the longer one (one side lacks the \REGISTRY\<hive> prefix).
        if (suffix_hit.empty()) {
            const auto& longer = kc.size() >= ec.size() ? kc : ec;
            const auto& shorter = kc.size() >= ec.size() ? ec : kc;
            if (IsSuffix(longer, shorter)) suffix_hit = k;
            else {
                const auto kh = StripHive(kc);
                const auto& lo = kh.size() >= ec_nohive.size() ? kh : ec_nohive;
                const auto& sh = kh.size() >= ec_nohive.size() ? ec_nohive : kh;
                if (!sh.empty() && IsSuffix(lo, sh)) suffix_hit = k;
            }
        }
    }
    return suffix_hit;
}

bool ProtectedRegistryStore::LookupProtectedKey(const std::wstring& event_key,
                                                uint32_t* out_category) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::wstring hit = MatchLocked(event_key);
    if (hit.empty()) return false;
    if (out_category) *out_category = keys_.at(hit).category;
    return true;
}

bool ProtectedRegistryStore::AddOwnerSigner(const std::wstring& canonical_key,
                                            const std::string& signer_subject) {
    if (canonical_key.empty() || signer_subject.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    keys_[canonical_key].owner_signers.insert(signer_subject);
    return true;
}

bool ProtectedRegistryStore::RemoveOwnerSigner(const std::wstring& canonical_key,
                                               const std::string& signer_subject) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = keys_.find(canonical_key);
    if (it == keys_.end()) return false;
    return it->second.owner_signers.erase(signer_subject) > 0;
}

bool ProtectedRegistryStore::IsAuthorizedSigner(const std::wstring& event_key,
                                                const std::string& signer_subject) const {
    if (signer_subject.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    std::wstring hit = MatchLocked(event_key);
    if (hit.empty()) return false;
    const auto& signers = keys_.at(hit).owner_signers;
    return signers.count(signer_subject) > 0;
}

size_t ProtectedRegistryStore::Count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return keys_.size();
}

CanonicalResourceIdentity ResolveCanonicalResourceIdentity(const std::wstring& path) {
    CanonicalResourceIdentity id;

    HANDLE handle = CreateFileW(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,  // lets this open directories too
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return id;
    }

    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileInformationByHandle(handle, &info)) {
        id.volume_serial = info.dwVolumeSerialNumber;
        id.file_reference_number =
            (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
        id.valid = true;
    }

    CloseHandle(handle);
    return id;
}

bool ProtectedResourceStore::AddProtectedResource(uint32_t volume_serial, uint64_t file_reference_number, uint32_t category) {
    std::lock_guard<std::mutex> lock(mutex_);
    resources_[Key{volume_serial, file_reference_number}] = category;
    return true;
}

bool ProtectedResourceStore::RemoveProtectedResource(uint32_t volume_serial, uint64_t file_reference_number) {
    std::lock_guard<std::mutex> lock(mutex_);
    return resources_.erase(Key{volume_serial, file_reference_number}) > 0;
}

bool ProtectedResourceStore::LookupProtectedResource(uint32_t volume_serial, uint64_t file_reference_number, uint32_t* out_category) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = resources_.find(Key{volume_serial, file_reference_number});
    if (it == resources_.end()) return false;
    if (out_category) *out_category = it->second;
    return true;
}

size_t ProtectedResourceStore::Count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return resources_.size();
}

bool ProtectedResourceStore::AddResourceOwnerSigner(uint32_t volume_serial, uint64_t file_reference_number, const std::string& signer_subject) {
    if (signer_subject.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    owner_signers_[Key{volume_serial, file_reference_number}].insert(signer_subject);
    return true;
}

bool ProtectedResourceStore::RemoveResourceOwnerSigner(uint32_t volume_serial, uint64_t file_reference_number, const std::string& signer_subject) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = owner_signers_.find(Key{volume_serial, file_reference_number});
    if (it == owner_signers_.end()) return false;
    return it->second.erase(signer_subject) > 0;
}

bool ProtectedResourceStore::IsAuthorizedSigner(uint32_t volume_serial, uint64_t file_reference_number, const std::string& signer_subject) const {
    if (signer_subject.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = owner_signers_.find(Key{volume_serial, file_reference_number});
    if (it == owner_signers_.end()) return false;
    return it->second.count(signer_subject) > 0;
}

bool ProtectedResourceStore::IsAuthorizedModifyingPath(uint32_t volume_serial, uint64_t file_reference_number,
                                                        const std::wstring& modifying_binary_path) const {
    auto signer = GetAuthenticodeSigner(modifying_binary_path);
    if (!signer) return false;  // unsigned/untrusted binary is never authorized
    return IsAuthorizedSigner(volume_serial, file_reference_number, *signer);
}

} // namespace kinnector::windows
