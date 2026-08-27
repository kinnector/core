#pragma once

#include <string>

namespace kinnector::windows {

// Translate an NT device path (\Device\HarddiskVolumeN\... - the form the
// Kernel-Process/Kernel-File ETW ImageName/FileName properties use) to a Win32
// drive path (C:\...). Returns the input unchanged if it isn't a \Device\ path
// or no mounted volume matches. Used wherever an ETW-sourced path has to be
// handed to a Win32 API (CreateFile, WinVerifyTrust).
std::wstring NtDevicePathToDos(const std::wstring& nt_path);

} // namespace kinnector::windows
