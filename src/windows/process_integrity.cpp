#include "process_integrity.h"

namespace kinnector::windows {

bool ProcessIntegrityStore::FlagProcessInjected(uint32_t pid, uint64_t create_time) {
    std::lock_guard<std::mutex> lock(mutex_);
    flagged_.insert(Key{pid, create_time});
    return true;
}

bool ProcessIntegrityStore::ClearProcessFlag(uint32_t pid, uint64_t create_time) {
    std::lock_guard<std::mutex> lock(mutex_);
    return flagged_.erase(Key{pid, create_time}) > 0;
}

bool ProcessIntegrityStore::IsProcessClear(uint32_t pid, uint64_t create_time) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flagged_.count(Key{pid, create_time}) == 0;  // default-allow: see header caveat
}

bool IsAuthorizedSelfUpdate(const ProtectedResourceStore& resources,
                             const ProcessIntegrityStore& integrity,
                             uint32_t volume_serial, uint64_t file_reference_number,
                             const std::wstring& modifying_binary_path,
                             uint32_t modifying_pid, uint64_t modifying_process_create_time) {
    return resources.IsAuthorizedModifyingPath(volume_serial, file_reference_number, modifying_binary_path) &&
           integrity.IsProcessClear(modifying_pid, modifying_process_create_time);
}

} // namespace kinnector::windows
