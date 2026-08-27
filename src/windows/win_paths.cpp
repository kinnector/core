#include "win_paths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <iterator>

namespace kinnector::windows {

std::wstring NtDevicePathToDos(const std::wstring& nt_path) {
    if (nt_path.size() < 8 || _wcsnicmp(nt_path.c_str(), L"\\Device\\", 8) != 0) {
        return nt_path;
    }
    wchar_t drives[512];
    DWORD n = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives) - 1), drives);
    if (n == 0) return nt_path;
    for (wchar_t* d = drives; *d; d += wcslen(d) + 1) {
        wchar_t letter[3] = { d[0], L':', 0 };
        wchar_t dev[MAX_PATH];
        if (!QueryDosDeviceW(letter, dev, MAX_PATH)) continue;
        size_t devlen = wcslen(dev);
        if (_wcsnicmp(nt_path.c_str(), dev, devlen) == 0 &&
            (nt_path.size() == devlen || nt_path[devlen] == L'\\')) {
            return std::wstring(letter) + nt_path.substr(devlen);
        }
    }
    return nt_path;
}

} // namespace kinnector::windows
