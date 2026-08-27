// WS2 (MVP_REACTIVE_PLAN.md) - protected registry keys.
//
// Part 1 (no elevation): CanonicalizeRegistryKey normalisation + the
// ProtectedRegistryStore matching rules (exact, subtree, hive-ambiguity
// tolerance).
// Part 2 (elevation): a real HKCU write is observed via Kernel-Registry ETW,
// and the emitted key_path - after the BaseObject chaining in etw_consumer.cpp -
// matches a key the "agent" registered by its HKCU\... path.

#include "etw_consumer.h"
#include "resource_identity.h"

#include <windows.h>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

using kinnector::windows::CanonicalizeRegistryKey;
using kinnector::windows::EtwConsumer;
using kinnector::windows::ProtectedRegistryStore;

#define CHECK(cond, msg)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" \
                      << std::endl;                                            \
            return 1;                                                          \
        }                                                                      \
    } while (0)

namespace {

std::mutex g_m;
std::condition_variable g_cv;
std::vector<TelemetryEvent> g_events;

void OnEvent(const TelemetryEvent& e) {
    std::lock_guard<std::mutex> lock(g_m);
    g_events.push_back(e);
    g_cv.notify_all();
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION el{};
    DWORD sz = sizeof(el);
    bool ok = GetTokenInformation(token, TokenElevation, &el, sizeof(el), &sz);
    CloseHandle(token);
    return ok && el.TokenIsElevated;
}

std::string Narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring Wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

constexpr int kSkip = 127;

} // namespace

static int Part1() {
    std::cout << "[Test] Part 1: canonicalisation + matching rules (no elevation)" << std::endl;

    CHECK(CanonicalizeRegistryKey(L"HKLM\\SOFTWARE\\Foo\\Bar") ==
              L"\\REGISTRY\\MACHINE\\SOFTWARE\\FOO\\BAR",
          "HKLM\\... canonicalises to \\REGISTRY\\MACHINE\\...");
    CHECK(CanonicalizeRegistryKey(L"HKEY_LOCAL_MACHINE/SOFTWARE//Foo/") ==
              L"\\REGISTRY\\MACHINE\\SOFTWARE\\FOO",
          "slashes, dup separators and trailing separator are normalised");
    CHECK(CanonicalizeRegistryKey(L"\\REGISTRY\\MACHINE\\SOFTWARE\\FOO") ==
              L"\\REGISTRY\\MACHINE\\SOFTWARE\\FOO",
          "an already-native path is stable");
    CHECK(CanonicalizeRegistryKey(L"HKU\\S-1-5-21-1-2-3\\Software\\X") ==
              L"\\REGISTRY\\USER\\S-1-5-21-1-2-3\\SOFTWARE\\X",
          "HKU\\<SID>\\... canonicalises to \\REGISTRY\\USER\\<SID>\\...");

    ProtectedRegistryStore store;
    const std::wstring run_key =
        CanonicalizeRegistryKey(L"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    CHECK(store.AddProtectedKey(run_key, 1, /*subtree=*/false), "registered the Run key");

    CHECK(store.LookupProtectedKey(run_key, nullptr), "exact match hits");
    CHECK(store.LookupProtectedKey(
              CanonicalizeRegistryKey(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"), nullptr),
          "a hive-relative path (ETW chain that didn't reach the root) still hits");
    CHECK(store.LookupProtectedKey(
              CanonicalizeRegistryKey(
                  L"HKU\\S-1-5-21-9-9-9\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
              nullptr),
          "the same relative Run path under a different hive also hits (safe superset "
          "for persistence protection)");
    CHECK(!store.LookupProtectedKey(
              CanonicalizeRegistryKey(
                  L"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"),
              nullptr),
          "an unrelated sibling key does NOT hit");

    const std::wstring vendor =
        CanonicalizeRegistryKey(L"HKLM\\Software\\Vendor");
    CHECK(store.AddProtectedKey(vendor, 2, /*subtree=*/true), "registered a subtree key");
    CHECK(store.LookupProtectedKey(
              CanonicalizeRegistryKey(L"HKLM\\Software\\Vendor\\Creds\\Token"), nullptr),
          "a descendant of a subtree key hits");
    CHECK(!store.LookupProtectedKey(
              CanonicalizeRegistryKey(L"HKLM\\Software\\VendorOther"), nullptr),
          "a sibling that merely shares a name prefix does NOT hit (component boundary)");

    CHECK(store.AddOwnerSigner(run_key, "Windows Update Vendor"), "added an owner signer");
    CHECK(store.IsAuthorizedSigner(
              CanonicalizeRegistryKey(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
              "Windows Update Vendor"),
          "authorised signer matches for a hive-relative event path");
    CHECK(!store.IsAuthorizedSigner(run_key, "Some Stealer"),
          "a non-allowlisted signer is not authorised");

    std::cout << "[Test] Part 1 OK" << std::endl;
    return 0;
}

static int Part2() {
    std::cout << "[Test] Part 2: real HKCU write observed via ETW matches the "
                 "registered key" << std::endl;
    EtwConsumer consumer;
    if (!consumer.Initialize()) {
        std::cerr << "[Test] EtwConsumer::Initialize failed" << std::endl;
        return 1;
    }
    consumer.SetEventCallback(OnEvent);
    if (!consumer.Start()) {
        std::cerr << "[Test] EtwConsumer::Start failed" << std::endl;
        return 1;
    }

    const std::wstring rel = L"Software\\KinnectorRegProt_" +
                             std::to_wstring(GetCurrentProcessId()) + L"\\creds";
    RegDeleteKeyW(HKEY_CURRENT_USER, rel.c_str());
    RegDeleteKeyW(HKEY_CURRENT_USER,
                  (L"Software\\KinnectorRegProt_" + std::to_wstring(GetCurrentProcessId())).c_str());

    HKEY hk = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, rel.c_str(), 0, nullptr, 0,
                              KEY_ALL_ACCESS, nullptr, &hk, nullptr);
    if (rc != ERROR_SUCCESS) { consumer.Stop(); std::cerr << "RegCreateKeyEx failed\n"; return 1; }
    DWORD v = 1;
    RegSetValueExW(hk, L"apitoken", 0, REG_DWORD, reinterpret_cast<BYTE*>(&v), sizeof(v));

    const std::string needle = "KinnectorRegProt_" + std::to_string(GetCurrentProcessId());
    std::string observed_key_path;
    {
        std::unique_lock<std::mutex> lock(g_m);
        bool got = g_cv.wait_for(lock, std::chrono::seconds(8), [&] {
            for (const auto& e : g_events) {
                if (e.header.event_type == EventType::RegistryWrite &&
                    std::string(e.details.registry_write.key_path).find(needle) != std::string::npos) {
                    observed_key_path = e.details.registry_write.key_path;
                    return true;
                }
            }
            return false;
        });
        if (!got) {
            RegCloseKey(hk);
            RegDeleteKeyW(HKEY_CURRENT_USER, rel.c_str());
            consumer.Stop();
            std::cerr << "[Test] timed out waiting for the RegistryWrite event\n";
            return 1;
        }
    }
    std::cout << "[Test] observed key_path = " << observed_key_path << std::endl;

    ProtectedRegistryStore store;
    // The "agent" registers the key by its HKCU path.
    const std::wstring registered =
        CanonicalizeRegistryKey(L"HKCU\\" + rel);
    store.AddProtectedKey(registered, 1, false);

    const std::wstring observed_canon = CanonicalizeRegistryKey(Wide(observed_key_path));
    std::wcout << L"[Test] registered canonical = " << registered << std::endl;
    std::wcout << L"[Test] observed  canonical = " << observed_canon << std::endl;

    CHECK(store.LookupProtectedKey(observed_canon, nullptr),
          "the ETW-observed write matches the key the agent registered");

    // Negative control: a different, unregistered key must not match.
    CHECK(!store.LookupProtectedKey(
              CanonicalizeRegistryKey(L"Software\\SomethingElse\\notprotected"), nullptr),
          "an unrelated key does not match");

    RegCloseKey(hk);
    RegDeleteKeyW(HKEY_CURRENT_USER, rel.c_str());
    RegDeleteKeyW(HKEY_CURRENT_USER,
                  (L"Software\\KinnectorRegProt_" + std::to_wstring(GetCurrentProcessId())).c_str());
    consumer.Stop();
    std::cout << "[Test] Part 2 OK" << std::endl;
    return 0;
}

int main() {
    std::cout << "=== Running Windows Registry Protection (WS2) Test ===" << std::endl;
    int rc = Part1();
    if (rc != 0) return rc;

    if (!IsElevated()) {
        std::cout << "[Test] Part 2 SKIPPED: not elevated (Kernel-Registry ETW "
                     "needs Administrator)." << std::endl;
        return kSkip;
    }
    rc = Part2();
    if (rc != 0) return rc;

    std::cout << "\n>>> TEST SUCCESSFUL! Registry protection validated. <<<" << std::endl;
    return 0;
}
