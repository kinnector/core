#include "authenticode.h"
#include "win_paths.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

namespace kinnector::windows {

namespace {

// Pull the leaf signer's simple display name out of a completed WinVerifyTrust
// state handle. Writes "" if it can't. Shared by the embedded and catalog paths.
void ExtractSigner(HANDLE state, char* out_signer, size_t max_len) {
    if (!out_signer || max_len == 0) return;
    out_signer[0] = '\0';
    if (!state) return;
    auto* prov = reinterpret_cast<CRYPT_PROVIDER_DATA*>(state);
    if (prov && prov->csSigners > 0 && prov->pasSigners &&
        prov->pasSigners[0].pasCertChain) {
        PCCERT_CONTEXT cert = prov->pasSigners[0].pasCertChain[0].pCert;
        if (cert) {
            CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                               out_signer, static_cast<DWORD>(max_len));
        }
    }
}

std::wstring HashToHex(const BYTE* hash, DWORD len) {
    static const wchar_t* kDigits = L"0123456789ABCDEF";
    std::wstring s;
    s.reserve(static_cast<size_t>(len) * 2);
    for (DWORD i = 0; i < len; ++i) {
        s += kDigits[hash[i] >> 4];
        s += kDigits[hash[i] & 0x0F];
    }
    return s;
}

// Embedded Authenticode check (WTD_CHOICE_FILE). Returns the raw WinVerifyTrust
// result; TRUST_E_NOSIGNATURE means "no embedded signature - try the catalog".
LONG VerifyEmbedded(const std::wstring& path, char* out_signer, size_t max_len) {
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &file_info;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    if (result == ERROR_SUCCESS) {
        ExtractSigner(wd.hWVTStateData, out_signer, max_len);
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    return result;
}

// Catalog-signing fallback: a real fraction of Windows system binaries and
// MSI-delivered binaries carry no embedded signature and are instead signed
// via a security catalog (.cat). Without this, they resolve as "unsigned" and
// a legitimately-signed vendor updater could be treated as an unauthorized
// modifier. (MVP_REACTIVE_PLAN.md WS3.)
bool VerifyCatalog(const std::wstring& path, char* out_signer, size_t max_len) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    HCATADMIN cat_admin = nullptr;
    // SHA-256 catalog hashing (Win8+). The GUID arg selects the default
    // "driver action" verification policy; nullptr is fine for file catalogs.
    if (!CryptCATAdminAcquireContext2(&cat_admin, nullptr, BCRYPT_SHA256_ALGORITHM,
                                      nullptr, 0)) {
        CloseHandle(file);
        return false;
    }

    DWORD hash_len = 0;
    CryptCATAdminCalcHashFromFileHandle2(cat_admin, file, &hash_len, nullptr, 0);
    if (hash_len == 0) {
        CryptCATAdminReleaseContext(cat_admin, 0);
        CloseHandle(file);
        return false;
    }
    std::vector<BYTE> hash(hash_len);
    if (!CryptCATAdminCalcHashFromFileHandle2(cat_admin, file, &hash_len, hash.data(), 0)) {
        CryptCATAdminReleaseContext(cat_admin, 0);
        CloseHandle(file);
        return false;
    }

    const std::wstring member_tag = HashToHex(hash.data(), hash_len);

    bool verified = false;
    HCATINFO cat_info = nullptr;
    for (;;) {
        HCATINFO next = CryptCATAdminEnumCatalogFromHash(cat_admin, hash.data(),
                                                         hash_len, 0, &cat_info);
        if (!next) {
            // The enum releases the handle we passed in and returns NULL at the
            // end - our copy is now dangling, don't double-release it.
            cat_info = nullptr;
            break;
        }
        cat_info = next;

        CATALOG_INFO ci = {};
        ci.cbStruct = sizeof(ci);
        if (!CryptCATCatalogInfoFromContext(cat_info, &ci, 0)) continue;

        WINTRUST_CATALOG_INFO wci = {};
        wci.cbStruct = sizeof(wci);
        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
        wci.pcwszMemberFilePath = path.c_str();
        wci.pcwszMemberTag = member_tag.c_str();
        wci.hMemberFile = file;
        wci.pbCalculatedFileHash = hash.data();
        wci.cbCalculatedFileHash = hash_len;
        wci.hCatAdmin = cat_admin;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA wd = {};
        wd.cbStruct = sizeof(wd);
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wd.pCatalog = &wci;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG result = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
        if (result == ERROR_SUCCESS) {
            ExtractSigner(wd.hWVTStateData, out_signer, max_len);
            verified = true;
        }
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

        if (verified) break;
    }

    if (cat_info) CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
    CryptCATAdminReleaseContext(cat_admin, 0);
    CloseHandle(file);
    return verified;
}

} // namespace

bool VerifyAuthenticodeSignature(const std::wstring& path, char* out_signer, size_t max_len) {
    if (out_signer && max_len > 0) out_signer[0] = '\0';
    if (path.empty()) return false;

    LONG embedded = VerifyEmbedded(path, out_signer, max_len);
    if (embedded == ERROR_SUCCESS) return true;

    // Only fall through to the catalog path when there simply is no embedded
    // signature. A present-but-invalid embedded signature (revoked, tampered,
    // untrusted root) is a real failure, not a catalog case.
    if (embedded == TRUST_E_NOSIGNATURE || embedded == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        embedded == static_cast<LONG>(TRUST_E_PROVIDER_UNKNOWN)) {
        return VerifyCatalog(path, out_signer, max_len);
    }
    return false;
}

namespace {

struct SignerCacheEntry {
    uint64_t file_size = 0;
    uint64_t last_write = 0;
    bool signed_ok = false;
    std::string signer;
};

std::mutex g_sig_cache_mutex;
std::unordered_map<std::wstring, SignerCacheEntry> g_sig_cache;
constexpr size_t kSigCacheCap = 16384;

bool ReadFileVersionKey(const std::wstring& path, uint64_t* size, uint64_t* lwt) {
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    bool ok = GetFileInformationByHandle(h, &info) != 0;
    CloseHandle(h);
    if (!ok) return false;
    *size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    *lwt = (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
           info.ftLastWriteTime.dwLowDateTime;
    return true;
}

} // namespace

namespace {

void CopyOut(const std::string& src, char* buf, size_t cap) {
    if (!buf || cap == 0) return;
    size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    memcpy(buf, src.data(), n);
    buf[n] = '\0';
}

} // namespace

bool PeekSignerCache(const std::wstring& raw_path, bool* out_signed,
                     char* out_signer, size_t max_len) {
    if (out_signer && max_len > 0) out_signer[0] = '\0';
    if (raw_path.empty()) return false;
    const std::wstring path = NtDevicePathToDos(raw_path);
    std::lock_guard<std::mutex> lock(g_sig_cache_mutex);
    auto it = g_sig_cache.find(path);
    if (it == g_sig_cache.end()) return false;
    if (out_signed) *out_signed = it->second.signed_ok;
    CopyOut(it->second.signer, out_signer, max_len);
    return true;
}

void WarmSignerCache(const std::wstring& raw_path) {
    char buf[256];
    CachedVerifyAuthenticodeSignature(raw_path, buf, sizeof(buf));
}

bool CachedVerifyAuthenticodeSignature(const std::wstring& raw_path, char* out_signer,
                                        size_t max_len) {
    if (out_signer && max_len > 0) out_signer[0] = '\0';
    if (raw_path.empty()) return false;

    const std::wstring path = NtDevicePathToDos(raw_path);

    uint64_t size = 0, lwt = 0;
    const bool have_key = ReadFileVersionKey(path, &size, &lwt);

    if (have_key) {
        std::lock_guard<std::mutex> lock(g_sig_cache_mutex);
        auto it = g_sig_cache.find(path);
        if (it != g_sig_cache.end() && it->second.file_size == size &&
            it->second.last_write == lwt) {
            CopyOut(it->second.signer, out_signer, max_len);
            return it->second.signed_ok;
        }
    }

    char buf[256] = {};
    bool ok = VerifyAuthenticodeSignature(path, buf, sizeof(buf));

    if (have_key) {
        std::lock_guard<std::mutex> lock(g_sig_cache_mutex);
        if (g_sig_cache.size() >= kSigCacheCap) g_sig_cache.clear();
        SignerCacheEntry e;
        e.file_size = size;
        e.last_write = lwt;
        e.signed_ok = ok;
        e.signer.assign(buf);
        g_sig_cache[path] = std::move(e);
    }

    CopyOut(buf, out_signer, max_len);
    return ok;
}

std::optional<std::string> GetAuthenticodeSigner(const std::wstring& path) {
    char signer[256];
    if (!VerifyAuthenticodeSignature(path, signer, sizeof(signer)) || signer[0] == '\0') {
        return std::nullopt;
    }
    return std::string(signer);
}

} // namespace kinnector::windows
