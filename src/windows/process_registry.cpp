#include "process_registry.h"
#include "authenticode.h"
#include "win_paths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <iterator>
#include <utility>

namespace kinnector::windows {

namespace {

uint64_t FiletimeToU64(const FILETIME& ft) {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// Resolve a PID's image to a Win32 path. Prefers a live query (works while the
// process is alive, returns a clean C:\ path); falls back to translating the
// ETW-supplied device path.
std::wstring ResolveImagePath(uint32_t pid, const std::wstring& etw_path) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        wchar_t buf[MAX_PATH * 2];
        DWORD len = static_cast<DWORD>(std::size(buf));
        bool ok = QueryFullProcessImageNameW(h, 0, buf, &len) != 0 && len > 0;
        CloseHandle(h);
        if (ok) return std::wstring(buf, len);
    }
    return NtDevicePathToDos(etw_path);
}

} // namespace

ProcessRegistry::ProcessRegistry() = default;

ProcessRegistry::~ProcessRegistry() { Stop(); }

void ProcessRegistry::Start() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (worker_running_) return;
        worker_running_ = true;
    }
    worker_ = std::thread(&ProcessRegistry::WorkerLoop, this);
    EnumerateExistingProcesses();
}

void ProcessRegistry::Stop() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (!worker_running_) return;
        worker_running_ = false;
    }
    queue_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

void ProcessRegistry::OnProcessStart(uint32_t pid, uint64_t sequence_number,
                                     uint64_t create_time,
                                     const std::wstring& image_path) {
    if (pid == 0) return;
    // Resolve the ETW device path to a Win32 path here (cheap: OpenProcess +
    // QueryFullProcessImageNameW, or a drive-letter table walk) rather than on
    // the worker - the worker can be seconds behind under ImageLoad load, and
    // consumers want a usable path immediately. Only the (slow) signer
    // verification is deferred to the worker.
    const std::wstring path = ResolveImagePath(pid, image_path);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ActorInfo info;
        info.sequence_number = sequence_number;
        info.create_time = create_time;
        info.image_path = path;
        info.signer_state = SignerState::Pending;
        by_pid_[pid] = std::move(info);  // overwrites any stale entry for a
                                         // reused PID - the whole point.
    }
    if (!path.empty()) EnqueueForVerification(pid, path);
}

void ProcessRegistry::OnProcessStop(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    by_pid_.erase(pid);
}

void ProcessRegistry::WarmSignerCache(const std::wstring& image_path) {
    if (!image_path.empty()) EnqueueForVerification(0, image_path);  // pid 0 = warm-only
}

bool ProcessRegistry::Lookup(uint32_t pid, ActorInfo* out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = by_pid_.find(pid);
    if (it == by_pid_.end()) return false;
    if (out) *out = it->second;
    return true;
}

uint64_t ProcessRegistry::SequenceNumberFor(uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = by_pid_.find(pid);
    return it == by_pid_.end() ? 0 : it->second.sequence_number;
}

size_t ProcessRegistry::Count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return by_pid_.size();
}

void ProcessRegistry::EnqueueForVerification(uint32_t pid,
                                             const std::wstring& image_path) {
    if (pid == 0) {
        // ImageLoad warm-cache backfill: skip if already cached, cap the queue.
        if (PeekSignerCache(image_path, nullptr, nullptr, 0)) return;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!worker_running_ || warm_queue_.size() >= kWarmQueueCap) return;
            warm_queue_.emplace_back(image_path);
        }
        queue_cv_.notify_one();
        return;
    }
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (!worker_running_) return;
        real_queue_.emplace_back(pid, image_path);
    }
    queue_cv_.notify_one();
}

void ProcessRegistry::WorkerLoop() {
    for (;;) {
        uint32_t pid = 0;
        std::wstring path;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !worker_running_ || !real_queue_.empty() || !warm_queue_.empty();
            });
            if (!worker_running_ && real_queue_.empty() && warm_queue_.empty()) return;
            if (!real_queue_.empty()) {
                pid = real_queue_.front().first;
                path = std::move(real_queue_.front().second);
                real_queue_.pop_front();
            } else {
                path = std::move(warm_queue_.front());
                warm_queue_.pop_front();
            }
        }

        if (pid == 0) {
            WarmSignerCache(path);  // populate the process-wide signer cache
            continue;
        }

        // Path was already resolved to a Win32 path in OnProcessStart; here we
        // only do the (slow) signer verification, deduped process-wide.
        char buf[256] = {};
        bool ok = CachedVerifyAuthenticodeSignature(path, buf, sizeof(buf));
        SignerState state = ok ? SignerState::Signed : SignerState::Unsigned;
        std::string signer = ok ? std::string(buf) : std::string();

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_pid_.find(pid);
        if (it != by_pid_.end() && it->second.image_path == path) {
            it->second.signer_state = state;
            it->second.signer_subject = signer;
        }
    }
}

void ProcessRegistry::EnumerateExistingProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    const uint32_t self = GetCurrentProcessId();

    if (Process32FirstW(snap, &pe)) {
        do {
            const uint32_t pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == self) continue;

            std::wstring full_path;
            uint64_t create_time = 0;

            HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (ph) {
                wchar_t buf[MAX_PATH * 2];
                DWORD len = static_cast<DWORD>(std::size(buf));
                if (QueryFullProcessImageNameW(ph, 0, buf, &len) && len > 0) {
                    full_path.assign(buf, len);
                }
                FILETIME ftc{}, fte{}, ftk{}, ftu{};
                if (GetProcessTimes(ph, &ftc, &fte, &ftk, &ftu)) {
                    create_time = FiletimeToU64(ftc);
                }
                CloseHandle(ph);
            }

            const std::wstring image_path =
                full_path.empty() ? std::wstring(pe.szExeFile) : full_path;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (by_pid_.count(pid)) continue;  // a live ProcessStart already
                                                   // filled this one - trust it.
                ActorInfo info;
                info.sequence_number = 0;  // pre-existing: no ETW sequence number.
                info.create_time = create_time;
                info.image_path = image_path;
                info.signer_state = SignerState::Pending;
                by_pid_[pid] = std::move(info);
            }

            // Only binaries we resolved a real full path for can be verified.
            if (!full_path.empty()) EnqueueForVerification(pid, full_path);
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
}

} // namespace kinnector::windows
