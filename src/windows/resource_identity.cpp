#include "resource_identity.h"
#include "authenticode.h"

#include <windows.h>

namespace kinnector::windows {

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
