#include "clipboard_helper.h"
#include <chrono>
#include <cstring>
#include <iostream>

namespace kinnector::windows {

namespace {
constexpr wchar_t kWindowClassName[] = L"KinnectorClipboardMonitorWnd";
}

ClipboardHelper* ClipboardHelper::instance_ = nullptr;

ClipboardHelper::ClipboardHelper()
    : hwnd_(nullptr), running_(false), sequence_(0) {}

ClipboardHelper::~ClipboardHelper() {
    Stop();
}

bool ClipboardHelper::Initialize() {
    instance_ = this;
    return true;
}

bool ClipboardHelper::Start() {
    if (running_) return false;
    running_ = true;
    thread_ = std::thread(&ClipboardHelper::MessageLoop, this);

    // AddClipboardFormatListener must run on the thread that owns hwnd_'s
    // message queue, so wait for MessageLoop() to actually create it before
    // reporting success/failure back to the caller.
    for (int i = 0; i < 100 && !hwnd_ && running_; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return hwnd_ != nullptr;
}

void ClipboardHelper::Stop() {
    if (!running_) return;
    running_ = false;
    if (hwnd_) {
        PostMessage(hwnd_, WM_CLOSE, 0, 0);
    }
    if (thread_.joinable()) thread_.join();
    hwnd_ = nullptr;
}

void ClipboardHelper::SetEventCallback(EventCallback cb) {
    callback_ = std::move(cb);
}

void ClipboardHelper::MessageLoop() {
    HINSTANCE hinst = GetModuleHandleW(nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &ClipboardHelper::WndProc;
    wc.hInstance = hinst;
    wc.lpszClassName = kWindowClassName;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, kWindowClassName, L"", 0, 0, 0, 0, 0,
                                 HWND_MESSAGE, nullptr, hinst, nullptr);
    if (!hwnd) {
        std::cerr << "[ClipboardHelper] CreateWindowExW failed: " << GetLastError() << std::endl;
        running_ = false;
        return;
    }

    if (!AddClipboardFormatListener(hwnd)) {
        std::cerr << "[ClipboardHelper] AddClipboardFormatListener failed: " << GetLastError() << std::endl;
    }

    // Publish hwnd_ only once the listener is fully armed, so Start() never
    // reports success before WM_CLIPBOARDUPDATE delivery is actually live.
    hwnd_ = hwnd;

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveClipboardFormatListener(hwnd);
    DestroyWindow(hwnd);
    UnregisterClassW(kWindowClassName, hinst);
}

LRESULT CALLBACK ClipboardHelper::WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (msg == WM_CLIPBOARDUPDATE && instance_) {
        instance_->OnClipboardUpdate();
        return 0;
    }
    if (msg == WM_CLOSE) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wparam, lparam);
}

void ClipboardHelper::OnClipboardUpdate() {
    if (!OpenClipboard(hwnd_)) {
        return;
    }

    std::string new_content;
    bool has_text_format = false;
    HANDLE data = GetClipboardData(CF_UNICODETEXT);
    if (data) {
        has_text_format = true;
        wchar_t* wtext = static_cast<wchar_t*>(GlobalLock(data));
        if (wtext) {
            int len = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                new_content.resize(static_cast<size_t>(len - 1));
                WideCharToMultiByte(CP_UTF8, 0, wtext, -1, new_content.data(), len, nullptr, nullptr);
            }
            GlobalUnlock(data);
        }
    }

    HWND owner = GetClipboardOwner();
    DWORD owner_pid = 0;
    if (owner) {
        GetWindowThreadProcessId(owner, &owner_pid);
    }
    bool is_foreground = owner != nullptr && owner == GetForegroundWindow();

    CloseClipboard();

    // Non-text clipboard content (image, files, ...) isn't attributable via
    // ClipboardWriteDetails' text fields - skip rather than emit a
    // misleading empty-string event.
    if (!has_text_format) {
        return;
    }

    if (new_content == last_content_) {
        return; // dedupe re-broadcasts of unchanged content
    }

    TelemetryEvent event{};
    event.header.sequence_number = ++sequence_;
    event.header.timestamp_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    event.header.pid = owner_pid;
    event.header.event_type = EventType::ClipboardWrite;
    event.header.source = TelemetrySource::Clipboard;

    ClipboardWriteDetails& details = event.details.clipboard_write;
    details.owner_pid = owner_pid;
    details.owner_is_foreground = is_foreground ? 1 : 0;
    std::strncpy(details.previous_content, last_content_.c_str(), sizeof(details.previous_content) - 1);
    std::strncpy(details.new_content, new_content.c_str(), sizeof(details.new_content) - 1);
    // Fine-grained content classification (crypto address formats etc.) is
    // policy-layer analysis, not Core's job (see README "What it does") -
    // Core reports the raw text plus attribution confidence only.
    std::strncpy(details.content_type, "TEXT", sizeof(details.content_type) - 1);
    std::strncpy(details.attribution, owner_pid != 0 ? "ATTRIBUTED" : "NULL_OWNER", sizeof(details.attribution) - 1);

    last_content_ = new_content;

    if (callback_) {
        callback_(event);
    }
}

}
