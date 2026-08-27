#include "file_guard.h"

#include <tdh.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <iostream>
#include <vector>

#pragma comment(lib, "tdh")

namespace kinnector::windows {

namespace {

// {EDD08927-9CC4-4E65-B970-C2560FB5C289} Microsoft-Windows-Kernel-File
const GUID kKernelFileGuid = {
    0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
constexpr USHORT kKernelFileCreateId = 12;
constexpr ULONGLONG kKernelFileCreateKeyword = 0x80;  // KERNEL_FILE_KEYWORD_CREATE
const wchar_t* const kCorrSessionName = L"KinnectorFileGuardSession";

std::wstring ToUpper(std::wstring s) {
    for (auto& c : s) c = towupper(c);
    return s;
}

// Extract the "FileName" string property from a Kernel-File event. Kept as
// cheap as possible - this runs on the dedicated session's callback thread for
// every file-create on the box. One TDH call into a fixed thread-local buffer;
// no size probe, no allocation.
std::wstring GetFileNameProperty(PEVENT_RECORD ev) {
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(L"FileName");
    pdd.ArrayIndex = ULONG_MAX;
    static thread_local wchar_t buf[1024];
    if (TdhGetProperty(ev, 0, nullptr, 1, &pdd, sizeof(buf),
                       reinterpret_cast<PBYTE>(buf)) != ERROR_SUCCESS)
        return {};
    buf[1023] = L'\0';
    return std::wstring(buf);
}

std::wstring Utf8ToWide(const char* utf8) {
    if (!utf8 || !utf8[0]) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w.data(), n);
    return w;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s(static_cast<size_t>(n) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

} // namespace

FileGuard* FileGuard::s_instance_ = nullptr;

FileGuard::FileGuard(EnforceFn enforce) : enforce_(std::move(enforce)) {}

FileGuard::~FileGuard() { Stop(); }

void FileGuard::Start() {
    if (running_.exchange(true)) return;
    s_instance_ = this;
    shutdown_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    rebuild_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    worker_ = std::thread(&FileGuard::WorkerLoop, this);
    if (!StartCorrelationSession()) {
        std::cerr << "[file_guard] dedicated correlation session unavailable - "
                     "falling back to the main consumer's FileCreate events\n";
    }
}

void FileGuard::Stop() {
    if (!running_.exchange(false)) return;
    StopCorrelationSession();
    if (shutdown_event_) SetEvent(shutdown_event_);
    {
        std::lock_guard<std::mutex> lk(corr_mutex_);
        corr_cv_.notify_all();
    }
    if (worker_.joinable()) worker_.join();
    s_instance_ = nullptr;

    // The worker has exited - it is now safe to tear guards down.
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& up : guards_) CloseGuard(*up);
    guards_.clear();
    for (auto& up : pending_add_) CloseGuard(*up);
    pending_add_.clear();
    pending_remove_.clear();
    if (shutdown_event_) { CloseHandle(shutdown_event_); shutdown_event_ = nullptr; }
    if (rebuild_event_) { CloseHandle(rebuild_event_); rebuild_event_ = nullptr; }
}

// static
void FileGuard::CloseGuard(Guard& g) {
    if (g.file != INVALID_HANDLE_VALUE) {
        CancelIoEx(g.file, &g.ov);
        CloseHandle(g.file);
        g.file = INVALID_HANDLE_VALUE;
    }
    if (g.ov.hEvent) { CloseHandle(g.ov.hEvent); g.ov.hEvent = nullptr; }
    g.armed = false;
}

// static
bool FileGuard::Arm(Guard& g) {
    if (!g.ov.hEvent) return false;

    // Re-open the handle fresh each arm cycle. After a break+ack the OS treats
    // the handle's oplock slot as spent - requesting a new oplock on it returns
    // ERROR_ACCESS_DENIED. A fresh handle sidesteps that.
    if (g.file != INVALID_HANDLE_VALUE) {
        CancelIoEx(g.file, &g.ov);
        CloseHandle(g.file);
        g.file = INVALID_HANDLE_VALUE;
    }
    g.file = CreateFileW(g.open_path.c_str(), FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (g.file == INVALID_HANDLE_VALUE) {
        std::cerr << "[file_guard] re-open failed for '" << WideToUtf8(g.key)
                  << "' (err " << GetLastError() << ")\n";
        g.armed = false;
        return false;
    }
    ResetEvent(g.ov.hEvent);

    g.in = {};
    g.in.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    g.in.StructureLength = sizeof(g.in);
    // RWH (read-write-handle): unlike RH, a foreign *read* open conflicts with
    // the W level, so it BREAKS and - critically - the OS blocks that open
    // pending our acknowledgement. An RH oplock would let the reader straight
    // through (reads are compatible with RH) and only notify us after the fact.
    g.in.RequestedOplockLevel =
        OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE | OPLOCK_LEVEL_CACHE_HANDLE;
    g.in.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

    g.out = {};
    g.out.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    g.out.StructureLength = sizeof(g.out);

    BOOL ok = DeviceIoControl(g.file, FSCTL_REQUEST_OPLOCK, &g.in, sizeof(g.in),
                              &g.out, sizeof(g.out), nullptr, &g.ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        g.armed = true;
        return true;
    }
    // ERROR_OPLOCK_NOT_GRANTED: another handle is already open to the file.
    // Any synchronous completion of a REQUEST is unexpected - treat as "not
    // monitoring" and let the worker retry.
    DWORD err = GetLastError();
    std::cerr << "[file_guard] oplock arm failed for '" << WideToUtf8(g.key)
              << "' (err " << err << ") - will retry\n";
    g.armed = false;
    return false;
}

bool FileGuard::AddGuard(const std::wstring& path) {
    if (path.empty() || !running_.load()) return false;

    auto g = std::make_unique<Guard>();
    g->key = ToUpper(path);
    g->open_path = path;

    HANDLE probe = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (probe == INVALID_HANDLE_VALUE) {
        std::cerr << "[file_guard] cannot open '" << WideToUtf8(path)
                  << "' (err " << GetLastError() << ")\n";
        return false;
    }
    BY_HANDLE_FILE_INFORMATION fi{};
    if (GetFileInformationByHandle(probe, &fi)) {
        g->volume_serial = fi.dwVolumeSerialNumber;
        g->frn = (static_cast<uint64_t>(fi.nFileIndexHigh) << 32) | fi.nFileIndexLow;
    }
    wchar_t dev[1024];
    DWORD n = GetFinalPathNameByHandleW(probe, dev, 1024,
                                        FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
    if (n > 0 && n < 1024) g->device_path = ToUpper(std::wstring(dev, n));
    CloseHandle(probe);
    if (g->device_path.empty()) {
        std::cerr << "[file_guard] could not resolve NT device path for '"
                  << WideToUtf8(path) << "' - correlation will not work\n";
    }

    g->ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    Arm(*g);  // opens the guard handle + requests the oplock; worker retries if it fails

    std::lock_guard<std::mutex> lock(mutex_);
    // Replace any existing pending-add for the same key.
    for (auto it = pending_add_.begin(); it != pending_add_.end(); ++it) {
        if ((*it)->key == g->key) { CloseGuard(**it); pending_add_.erase(it); break; }
    }
    pending_add_.push_back(std::move(g));
    if (rebuild_event_) SetEvent(rebuild_event_);

    std::cout << "[file_guard] guarding '" << WideToUtf8(path) << "'\n";
    return true;
}

bool FileGuard::RemoveGuard(const std::wstring& path) {
    if (path.empty()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    pending_remove_.push_back(ToUpper(path));
    if (rebuild_event_) SetEvent(rebuild_event_);
    return true;
}

size_t FileGuard::Count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return guards_.size() + pending_add_.size();
}

void FileGuard::DrainPending() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& up : pending_add_) {
        for (auto it = guards_.begin(); it != guards_.end(); ++it) {
            if ((*it)->key == up->key) { CloseGuard(**it); guards_.erase(it); break; }
        }
        guards_.push_back(std::move(up));
    }
    pending_add_.clear();

    for (const auto& key : pending_remove_) {
        for (auto it = guards_.begin(); it != guards_.end(); ++it) {
            if ((*it)->key == key) {
                CloseGuard(**it);
                guards_.erase(it);
                std::cout << "[file_guard] removed guard '" << WideToUtf8(key) << "'\n";
                break;
            }
        }
    }
    pending_remove_.clear();
}

void FileGuard::WorkerLoop() {
    while (running_.load()) {
        DrainPending();

        std::vector<HANDLE> handles;
        std::vector<Guard*> owners;
        handles.push_back(shutdown_event_); owners.push_back(nullptr);
        handles.push_back(rebuild_event_);  owners.push_back(nullptr);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& up : guards_) {
                if (up->armed && handles.size() < MAXIMUM_WAIT_OBJECTS) {
                    handles.push_back(up->ov.hEvent);
                    owners.push_back(up.get());
                }
            }
        }

        DWORD r = WaitForMultipleObjects(static_cast<DWORD>(handles.size()),
                                         handles.data(), FALSE, 2000);

        if (r == WAIT_OBJECT_0) break;                       // shutdown
        if (r == WAIT_OBJECT_0 + 1) continue;                // rebuild (auto-reset)
        if (r == WAIT_TIMEOUT) {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& up : guards_) if (!up->armed) Arm(*up);
            continue;
        }
        if (r >= WAIT_OBJECT_0 + 2 && r < WAIT_OBJECT_0 + handles.size()) {
            Guard* g = owners[r - WAIT_OBJECT_0];
            if (g && running_.load()) HandleBreak(*g);
        }
        // WAIT_FAILED / abandoned: loop, DrainPending + rebuild will re-sync.
    }
}

void FileGuard::HandleBreak(Guard& g) {
    // Consume the completed REQUEST ioctl so g.ov can be reused.
    DWORD bytes = 0;
    GetOverlappedResult(g.file, &g.ov, &bytes, FALSE);
    g.armed = false;

    const DWORD t0 = GetTickCount();

    // The foreign opener is blocked in the kernel pending our Acknowledge().
    // Correlate it to a pid, decide, suspend if UNAUTHORIZED, THEN ack - so an
    // unauthorized opener resumes already suspended and never completes its
    // read.
    const bool vetted_recent =
        g.vetted_pid != 0 && (GetTickCount() - g.vetted_tick) < kVettedGraceMs;
    // A break while a just-decided opener is still active is very likely that
    // opener's own ReadFile (no CREATE event -> never correlates). Don't burn
    // the full hold budget waiting on it; a genuine fresh opener still
    // correlates inside the short window.
    const DWORD budget = vetted_recent ? kVettedCorrelationMs : kCorrelationBudgetMs;

    std::vector<uint32_t> candidates;
    {
        std::unique_lock<std::mutex> lk(corr_mutex_);
        if (!g.device_path.empty()) {
            corr_want_ = g.device_path;
            corr_pids_.clear();
            corr_cv_.wait_for(lk, std::chrono::milliseconds(budget),
                              [&] { return !corr_pids_.empty() || !running_.load(); });
            if (!corr_pids_.empty() && running_.load())
                corr_cv_.wait_for(lk, std::chrono::milliseconds(kCollectExtraMs),
                                  [&] { return !running_.load(); });
            candidates = corr_pids_;
            corr_want_.clear();
            corr_pids_.clear();
        }
    }

    // Fast path: a read / metadata break by the opener we just decided on (a
    // ReadFile emits no Kernel-File CREATE event, so it never correlates).
    // Don't re-hold it.
    bool fast_path = false;
    if (candidates.empty() && vetted_recent) {
        fast_path = true;
    } else if (vetted_recent) {
        for (uint32_t c : candidates)
            if (c == g.vetted_pid) { fast_path = true; break; }
    }

    EnforceResult res;
    if (!fast_path && !candidates.empty() && running_.load() && enforce_) {
        try {
            res = enforce_(candidates, g.volume_serial, g.frn);
        } catch (...) {
            res = {};
        }
    }
    if (res.verdict != Verdict::FailOpen && res.pid != 0) {
        g.vetted_pid = res.pid;
        g.vetted_tick = GetTickCount();
    }

    Acknowledge(g);

    const DWORD held = GetTickCount() - t0;
    const char* v = res.verdict == Verdict::Suspended  ? "suspended opener"
                    : res.verdict == Verdict::Authorized ? "authorized"
                    : fast_path                          ? "vetted (fast path)"
                    : candidates.empty()                 ? "uncorrelated - fail open"
                                                         : "no action - fail open";
    std::cout << "[file_guard] break on '" << WideToUtf8(g.key) << "': " << v
              << " (held " << held << "ms)\n";

    // A hot file (AV real-time scan, indexer) can re-break the instant we
    // re-arm. Once we see a run of breaks we cannot correlate or that just
    // hit the vetted fast-path, ease off so we are not holding innocent
    // accesses for a full correlation budget each time.
    if (candidates.empty() && !fast_path) {
        if (++g.uncorrelated_run >= 2) {
            Sleep(g.uncorrelated_run >= 4 ? 2000 : 400);
        }
    } else {
        g.uncorrelated_run = 0;
    }
    g.last_break_tick = GetTickCount();

    Arm(g);  // re-arm for the next opener
}

void FileGuard::Acknowledge(Guard& g) {
    if (!(g.out.Flags & REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED)) return;

    REQUEST_OPLOCK_INPUT_BUFFER in{};
    in.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    in.StructureLength = sizeof(in);
    in.RequestedOplockLevel = 0;  // release entirely; Arm() re-requests fresh
    in.Flags = REQUEST_OPLOCK_INPUT_FLAG_ACK;

    REQUEST_OPLOCK_OUTPUT_BUFFER out{};
    out.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    out.StructureLength = sizeof(out);

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL ok = DeviceIoControl(g.file, FSCTL_REQUEST_OPLOCK, &in, sizeof(in),
                              &out, sizeof(out), nullptr, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        WaitForSingleObject(ov.hEvent, 2000);
        DWORD bytes = 0;
        GetOverlappedResult(g.file, &ov, &bytes, FALSE);
    }
    if (ov.hEvent) CloseHandle(ov.hEvent);
}

void FileGuard::NotifyFileCreate(const char* file_path_utf8, uint32_t pid) {
    if (!file_path_utf8 || !file_path_utf8[0] || pid == 0) return;
    // Our own process opening a guarded file (the guard handle itself, identity
    // resolution, tests) is never the threat - and letting it into the ring
    // would mis-correlate a later foreign break to us.
    if (pid == GetCurrentProcessId()) return;
    std::wstring p = ToUpper(Utf8ToWide(file_path_utf8));
    if (p.empty()) return;

    std::lock_guard<std::mutex> lk(corr_mutex_);
    recent_[recent_idx_] = RecentOpen{p, pid, GetTickCount()};
    recent_idx_ = (recent_idx_ + 1) % recent_.size();

    if (!corr_want_.empty() && p == corr_want_) {
        if (corr_pids_.size() < 8 &&
            std::find(corr_pids_.begin(), corr_pids_.end(), pid) == corr_pids_.end())
            corr_pids_.push_back(pid);
        corr_cv_.notify_all();
    }
}

// ── dedicated Kernel-File CREATE ETW session ────────────────────────────────

bool FileGuard::StartCorrelationSession() {
    const ULONG name_len =
        static_cast<ULONG>((wcslen(kCorrSessionName) + 1) * sizeof(WCHAR));
    const ULONG props_size = sizeof(EVENT_TRACE_PROPERTIES) + name_len;

    auto fill_props = [&](std::vector<BYTE>& b) -> EVENT_TRACE_PROPERTIES* {
        b.assign(props_size, 0);
        auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(b.data());
        p->Wnode.BufferSize = props_size;
        p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->Wnode.ClientContext = 2;  // system-time clock
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p->FlushTimer = 1;
        // CREATE turns out to be the single highest-volume kernel-file event
        // (~90% of file events on a busy box), so this session is not as light
        // as hoped - give it real headroom so it stays inside the hold budget.
        p->BufferSize = 64;      // KB
        p->MinimumBuffers = 16;
        p->MaximumBuffers = 64;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        return p;
    };

    std::vector<BYTE> buf;
    EVENT_TRACE_PROPERTIES* props = fill_props(buf);
    ControlTraceW(0, kCorrSessionName, props, EVENT_TRACE_CONTROL_STOP);

    props = fill_props(buf);
    ULONG status = StartTraceW(&corr_session_, kCorrSessionName, props);
    for (int attempt = 0; status == ERROR_ALREADY_EXISTS && attempt < 5; ++attempt) {
        Sleep(200);
        std::vector<BYTE> sbuf;
        EVENT_TRACE_PROPERTIES* sp = fill_props(sbuf);
        ControlTraceW(0, kCorrSessionName, sp, EVENT_TRACE_CONTROL_STOP);
        props = fill_props(buf);
        status = StartTraceW(&corr_session_, kCorrSessionName, props);
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "[file_guard] StartTrace(correlation) failed: " << status << "\n";
        corr_session_ = 0;
        return false;
    }

    ENABLE_TRACE_PARAMETERS etp{};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(corr_session_, &kKernelFileGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION,
                            kKernelFileCreateKeyword, 0, 0, &etp);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[file_guard] EnableTraceEx2(Kernel-File) failed: " << status << "\n";
        StopCorrelationSession();
        return false;
    }

    corr_thread_ = CreateThread(nullptr, 0, CorrelationTraceThread, this, 0, nullptr);
    if (!corr_thread_) {
        StopCorrelationSession();
        return false;
    }
    return true;
}

void FileGuard::StopCorrelationSession() {
    if (corr_session_) {
        const ULONG name_len =
            static_cast<ULONG>((wcslen(kCorrSessionName) + 1) * sizeof(WCHAR));
        const ULONG props_size = sizeof(EVENT_TRACE_PROPERTIES) + name_len;
        std::vector<BYTE> b(props_size, 0);
        auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(b.data());
        p->Wnode.BufferSize = props_size;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(corr_session_, nullptr, p, EVENT_TRACE_CONTROL_STOP);
        corr_session_ = 0;
    }
    if (corr_trace_) {
        CloseTrace(corr_trace_);
        corr_trace_ = 0;
    }
    if (corr_thread_) {
        WaitForSingleObject(corr_thread_, 5000);
        CloseHandle(corr_thread_);
        corr_thread_ = nullptr;
    }
}

// static
DWORD WINAPI FileGuard::CorrelationTraceThread(LPVOID param) {
    auto* self = static_cast<FileGuard*>(param);
    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = const_cast<LPWSTR>(kCorrSessionName);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &FileGuard::CorrelationCallback;

    TRACEHANDLE th = OpenTraceW(&log);
    if (th == INVALID_PROCESSTRACE_HANDLE) return 1;
    self->corr_trace_ = th;

    ProcessTrace(&th, 1, nullptr, nullptr);  // blocks until CloseTrace
    return 0;
}

// static
void WINAPI FileGuard::CorrelationCallback(PEVENT_RECORD event) {
    FileGuard* self = s_instance_;
    if (!self || !event) return;
    if (event->EventHeader.EventDescriptor.Id != kKernelFileCreateId) return;
    // Cheap early-outs before any TDH work (this fires for every create on the
    // box). Our own opens and system pids are never the guarded-file threat.
    const uint32_t pid = event->EventHeader.ProcessId;
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) return;
    if (!IsEqualGUID(event->EventHeader.ProviderId, kKernelFileGuid)) return;

    std::wstring name = GetFileNameProperty(event);
    if (name.empty()) return;
    char utf8[1024];
    int n = WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, utf8, sizeof(utf8),
                                nullptr, nullptr);
    if (n <= 0) return;
    self->NotifyFileCreate(utf8, event->EventHeader.ProcessId);
}

} // namespace kinnector::windows
