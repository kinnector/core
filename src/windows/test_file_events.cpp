#include "etw_consumer.h"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>
#include <string>
#include <algorithm>
#include <cctype>

using kinnector::windows::EtwConsumer;

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::vector<TelemetryEvent> g_events;

void OnEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.push_back(event);
    g_cv.notify_all();
}

// ETW captures NT device-namespace paths (\Device\HarddiskVolumeN\...), not
// drive-letter paths - match on whether the captured path ends with our
// chosen unique filename rather than full-path equality.
bool EndsWithIgnoreCase(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin(),
                       [](char a, char b) { return tolower(a) == tolower(b); });
}

template <typename Pred>
bool WaitForEvent(EventType type, Pred pred, TelemetryEvent* out, int timeout_ms) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
        for (const auto& ev : g_events) {
            if (ev.header.event_type == type && pred(ev)) {
                *out = ev;
                return true;
            }
        }
        return false;
    });
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

} // namespace

// This project builds Release/-DNDEBUG (see core/CLAUDE.md) - assert() is
// elided, so every check here is a real if/return, not assert().
#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            consumer.Stop(); \
            return 1; \
        } \
    } while (0)

// Same elevation requirement/skip-not-mock pattern as test_process_lineage.cpp.
static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows File Events (write/rename/delete) Test ===" << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not running elevated (Administrator) - "
                     "real Kernel-File ETW tracing requires it. "
                     "Re-run this test from an elevated session to actually validate it."
                  << std::endl;
        return kSkipReturnCode;
    }

    EtwConsumer consumer;
    if (!consumer.Initialize()) {
        std::cerr << "[Test] EtwConsumer::Initialize failed even though elevated" << std::endl;
        return 1;
    }
    consumer.SetEventCallback(OnEvent);
    if (!consumer.Start()) {
        std::cerr << "[Test] EtwConsumer::Start failed" << std::endl;
        return 1;
    }

    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    DWORD pid = GetCurrentProcessId();
    std::wstring base = std::wstring(temp_dir) + L"kinnector_test_file_events_" + std::to_wstring(pid);
    std::wstring path1 = base + L".txt";
    std::wstring path2 = base + L"_renamed.txt";
    std::string filename1_narrow = "kinnector_test_file_events_" + std::to_string(pid) + ".txt";
    std::string filename2_narrow = "kinnector_test_file_events_" + std::to_string(pid) + "_renamed.txt";

    DeleteFileW(path1.c_str());
    DeleteFileW(path2.c_str());

    const std::string content = "kinnector file event test payload";

    std::cout << "[Test] Writing file..." << std::endl;
    {
        std::ofstream ofs(path1, std::ios::binary);
        ofs << content;
    }

    TelemetryEvent write_ev{};
    bool got_write = WaitForEvent(EventType::FileWrite, [&](const TelemetryEvent& ev) {
        return EndsWithIgnoreCase(ev.details.file_write.file_path, filename1_narrow);
    }, &write_ev, 5000);
    CHECK(got_write, "FileWrite event observed for the written file");
    CHECK(write_ev.details.file_write.bytes_written == content.size(),
          "bytes_written matches the actual content length");
    std::cout << "[Test] FileWrite: path=" << write_ev.details.file_write.file_path
              << " bytes_written=" << write_ev.details.file_write.bytes_written << std::endl;

    std::cout << "[Test] Renaming file..." << std::endl;
    CHECK(MoveFileW(path1.c_str(), path2.c_str()), "MoveFileW succeeded");

    TelemetryEvent rename_ev{};
    bool got_rename = WaitForEvent(EventType::FileRename, [&](const TelemetryEvent& ev) {
        return EndsWithIgnoreCase(ev.details.file_rename.destination_path, filename2_narrow);
    }, &rename_ev, 5000);
    CHECK(got_rename, "FileRename event observed with matching destination path");
    CHECK(EndsWithIgnoreCase(rename_ev.details.file_rename.source_path, filename1_narrow),
          "FileRename source_path resolved via the FileObject cache matches the original file");
    std::cout << "[Test] FileRename: source=" << rename_ev.details.file_rename.source_path
              << " destination=" << rename_ev.details.file_rename.destination_path << std::endl;

    std::cout << "[Test] Deleting file..." << std::endl;
    CHECK(DeleteFileW(path2.c_str()), "DeleteFileW succeeded");

    TelemetryEvent delete_ev{};
    bool got_delete = WaitForEvent(EventType::FileDelete, [&](const TelemetryEvent& ev) {
        return EndsWithIgnoreCase(ev.details.file_delete.file_path, filename2_narrow);
    }, &delete_ev, 5000);
    CHECK(got_delete, "FileDelete event observed for the renamed-then-deleted file");
    std::cout << "[Test] FileDelete: path=" << delete_ev.details.file_delete.file_path << std::endl;

    consumer.Stop();
    std::cout << "\n>>> TEST SUCCESSFUL! Write/rename/delete file events validated. <<<" << std::endl;
    return 0;
}
