#include "clipboard_helper.h"
#include <windows.h>
#include <iostream>
#include <cstring>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>
#include <thread>

using kinnector::windows::ClipboardHelper;

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::vector<TelemetryEvent> g_events;

void OnEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.push_back(event);
    g_cv.notify_all();
}

bool WaitForEventCount(size_t count, int timeout_ms) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [count] { return g_events.size() >= count; });
}

// Writes text with a real owner window, matching how a real clipboard-writing
// app (browser, wallet client, ...) would own the clipboard --
// OpenClipboard(nullptr) would leave GetClipboardOwner() at NULL and defeat
// the attribution checks below.
bool SetClipboardText(HWND owner, const wchar_t* text) {
    if (!OpenClipboard(owner)) {
        std::cerr << "[Test] OpenClipboard failed: " << GetLastError() << std::endl;
        return false;
    }
    EmptyClipboard();
    size_t bytes = (wcslen(text) + 1) * sizeof(wchar_t);
    HGLOBAL hmem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hmem) {
        std::cerr << "[Test] GlobalAlloc failed: " << GetLastError() << std::endl;
        CloseClipboard();
        return false;
    }
    void* ptr = GlobalLock(hmem);
    memcpy(ptr, text, bytes);
    GlobalUnlock(hmem);
    if (!SetClipboardData(CF_UNICODETEXT, hmem)) {
        std::cerr << "[Test] SetClipboardData failed: " << GetLastError() << std::endl;
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}

} // namespace

// This project builds Release/-DNDEBUG (see core/CLAUDE.md), which silently
// elides assert() - every correctness check here uses a real if/return
// instead, not assert().
#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            helper.Stop(); \
            return 1; \
        } \
    } while (0)

int main() {
    std::cout << "=== Running Windows Clipboard Helper Test ===" << std::endl;

    HINSTANCE hinst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = hinst;
    wc.lpszClassName = L"KinnectorClipboardTestOwnerWnd";
    RegisterClassExW(&wc);
    HWND owner = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0,
                                  HWND_MESSAGE, nullptr, hinst, nullptr);
    if (!owner) {
        std::cerr << "[Test] Failed to create owner window: " << GetLastError() << std::endl;
        return 1;
    }

    ClipboardHelper helper;
    if (!helper.Initialize()) {
        std::cerr << "[Test] ClipboardHelper::Initialize failed" << std::endl;
        return 1;
    }
    helper.SetEventCallback(OnEvent);

    if (!helper.Start()) {
        std::cerr << "[Test] Failed to start ClipboardHelper" << std::endl;
        return 1;
    }

    std::cout << "[Test] Writing first clipboard value..." << std::endl;
    CHECK(SetClipboardText(owner, L"hello kinnector"), "first SetClipboardText");

    if (!WaitForEventCount(1, 5000)) {
        std::cerr << "[Test] Timed out waiting for first ClipboardWrite event" << std::endl;
        helper.Stop();
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const TelemetryEvent& ev = g_events[0];
        CHECK(ev.header.event_type == EventType::ClipboardWrite, "event_type");
        CHECK(ev.header.source == TelemetrySource::Clipboard, "source");
        CHECK(std::strcmp(ev.details.clipboard_write.new_content, "hello kinnector") == 0, "new_content");
        CHECK(std::strcmp(ev.details.clipboard_write.previous_content, "") == 0, "previous_content empty on first write");
        CHECK(ev.details.clipboard_write.owner_pid == GetCurrentProcessId(), "owner_pid");
        CHECK(std::strcmp(ev.details.clipboard_write.attribution, "ATTRIBUTED") == 0, "attribution");
        std::cout << "[Test] First event validated (owner_pid=" << ev.details.clipboard_write.owner_pid << ")" << std::endl;
    }

    std::cout << "[Test] Writing second clipboard value (checks previous_content threading)..." << std::endl;
    CHECK(SetClipboardText(owner, L"second value"), "second SetClipboardText");

    if (!WaitForEventCount(2, 5000)) {
        std::cerr << "[Test] Timed out waiting for second ClipboardWrite event" << std::endl;
        helper.Stop();
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const TelemetryEvent& ev = g_events[1];
        CHECK(std::strcmp(ev.details.clipboard_write.new_content, "second value") == 0, "new_content #2");
        CHECK(std::strcmp(ev.details.clipboard_write.previous_content, "hello kinnector") == 0, "previous_content #2");
        std::cout << "[Test] Second event validated." << std::endl;
    }

    std::cout << "[Test] Re-writing identical value (checks dedupe)..." << std::endl;
    CHECK(SetClipboardText(owner, L"second value"), "third SetClipboardText");

    bool got_third = WaitForEventCount(3, 1500);
    CHECK(!got_third, "duplicate clipboard content must not emit a second event");
    std::cout << "[Test] Dedupe validated." << std::endl;

    helper.Stop();
    DestroyWindow(owner);
    UnregisterClassW(L"KinnectorClipboardTestOwnerWnd", hinst);

    std::cout << "\n>>> TEST SUCCESSFUL! Clipboard capture, attribution, and dedupe validated. <<<" << std::endl;
    return 0;
}
