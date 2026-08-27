// list_process_modules_windows - interim hardening layer 3.
//
// Audits THIS process's own modules (OpenProcess on self always succeeds, no
// elevation needed) and checks: count is sane, our own image is listed, and
// the system DLLs resolve a Microsoft signer via the catalog fallback.

#include "kinnector/ffi.h"

#include <windows.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::cout << "=== Running Windows Module Audit Test ===" << std::endl;

    std::vector<char> buf(256 * 1024);
    int32_t count = list_process_modules_windows(GetCurrentProcessId(),
                                                 buf.data(), buf.size());

    std::cout << "[Test] list_process_modules_windows -> " << count << std::endl;
    if (count <= 0) {
        std::cerr << "[Test] FAIL: expected a positive module count" << std::endl;
        return 1;
    }

    const std::string out(buf.data());
    // Count lines and look for the markers we expect.
    int lines = 0;
    bool saw_ntdll_signed = false, saw_self = false;
    size_t start = 0;
    while (start < out.size()) {
        size_t nl = out.find('\n', start);
        if (nl == std::string::npos) break;
        std::string line = out.substr(start, nl - start);
        start = nl + 1;
        ++lines;
        size_t tab = line.find('\t');
        if (tab == std::string::npos) { std::cerr << "[Test] FAIL: no tab in line: " << line << "\n"; return 1; }
        std::string path = line.substr(0, tab);
        std::string signer = line.substr(tab + 1);

        std::string lower = path;
        for (auto& c : lower) c = (char)tolower(c);
        if (lower.find("ntdll.dll") != std::string::npos) {
            std::cout << "[Test] ntdll signer='" << signer << "'\n";
            if (signer.find("Microsoft") != std::string::npos) saw_ntdll_signed = true;
        }
        if (lower.find("test-module-audit") != std::string::npos ||
            lower.find("test_module_audit") != std::string::npos)
            saw_self = true;
    }

    std::cout << "[Test] parsed " << lines << " module lines\n";
    if (lines < 3)          { std::cerr << "[Test] FAIL: too few module lines\n"; return 1; }
    if (!saw_ntdll_signed)  { std::cerr << "[Test] FAIL: ntdll did not resolve a Microsoft signer "
                                           "(catalog fallback broken?)\n"; return 1; }
    if (!saw_self)          { std::cerr << "[Test] FAIL: own image not in the module list\n"; return 1; }

    // -1 path: a pid that does not exist.
    if (list_process_modules_windows(0xFFFFFFF0u, buf.data(), buf.size()) != -1) {
        std::cerr << "[Test] FAIL: expected -1 for a bogus pid\n";
        return 1;
    }

    std::cout << "\n>>> TEST SUCCESSFUL! Module audit works (ntdll signed, self listed). <<<"
              << std::endl;
    return 0;
}
