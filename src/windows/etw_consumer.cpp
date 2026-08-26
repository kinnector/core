// Fix 3: Full ETW Consumer implementation replacing the non-functional stub.
//
// Subscribes to three Microsoft kernel ETW providers:
//   - Microsoft-Windows-Kernel-Process  (ProcessCreate, ImageLoad)
//   - Microsoft-Windows-Kernel-File     (FileCreate, FileIORead)
//   - Microsoft-Windows-Kernel-Network  (NetworkConnect via TcpIp/UdpIp)
//
// Events are parsed with TdhGetEventInformation and forwarded as TelemetryEvent
// structs through the registered callback (→ IPC pipe → Rust agent).
//
// Fix 4: VerifyAuthenticodeSignature now calls WinVerifyTrust with the full
// Authenticode chain validation action instead of the path-string stub.

#include "etw_consumer.h"
#include "authenticode.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wintrust.h>
#include <softpub.h>
#include <tdh.h>
#include <evntrace.h>
#include <evntcons.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "tdh")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "advapi32")

namespace kinnector::windows {

// ─────────────────────────────────────────────────────────────────────────────
// ETW Provider GUIDs
// ─────────────────────────────────────────────────────────────────────────────

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} Microsoft-Windows-Kernel-Process
static const GUID KernelProcessGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b,
    { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 }
};

// {EDD08927-9CC4-4E65-B970-C2560FB5C289} Microsoft-Windows-Kernel-File
static const GUID KernelFileGuid = {
    0xedd08927, 0x9cc4, 0x4e65,
    { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 }
};

// {7DD42A49-5329-4832-8DFD-43D979153A88} Microsoft-Windows-Kernel-Network
static const GUID KernelNetworkGuid = {
    0x7dd42a49, 0x5329, 0x4832,
    { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
};

// {70EB4F03-C1DE-4F73-A051-33D13D5413BD} Microsoft-Windows-Kernel-Registry
// (verified via `logman query providers "Microsoft-Windows-Kernel-Registry"`
// on this machine - see WINDOWS_COVERAGE_PLAN.md Phase 3.)
static const GUID KernelRegistryGuid = {
    0x70eb4f03, 0xc1de, 0x4f73,
    { 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd }
};

// {DE7B24EA-73C8-4A09-985D-5BDADCFA9017} Microsoft-Windows-TaskScheduler
// (verified via `logman query providers "Microsoft-Windows-TaskScheduler"`
// on this machine - see WINDOWS_COVERAGE_PLAN.md Phase 3.)
static const GUID TaskSchedulerGuid = {
    0xde7b24ea, 0x73c8, 0x4a09,
    { 0x98, 0x5d, 0x5b, 0xda, 0xdc, 0xfa, 0x90, 0x17 }
};

// {89FE8F40-CDCE-464E-8217-15EF97D4C7C3} Microsoft-Windows-Crypto-DPAPI
// (verified via `logman query providers "Microsoft-Windows-Crypto-DPAPI"` on
// this machine - see WINDOWS_COVERAGE_PLAN.md Phase 6.)
static const GUID DpapiGuid = {
    0x89fe8f40, 0xcdce, 0x464e,
    { 0x82, 0x17, 0x15, 0xef, 0x97, 0xd4, 0xc7, 0xc3 }
};

// {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} Microsoft-Windows-Threat-Intelligence
// (ETW-TI). Undocumented by Microsoft; GUID is publicly known from prior
// security research. Per WINDOWS_COVERAGE_PLAN.md Phase 4, EnableTraceEx2
// against this provider requires the calling process to run as
// Antimalware-PPL - on an ordinary elevated session it will fail with
// ACCESS_DENIED, same as every other EnableTraceEx2 call here, that failure
// is logged and non-fatal rather than aborting Initialize().
static const GUID ThreatIntelGuid = {
    0xf4e1897c, 0xbb5d, 0x5668,
    { 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44 }
};

// Event IDs for Microsoft-Windows-Kernel-Process
static constexpr USHORT KERNEL_PROCESS_CREATE     = 1;
static constexpr USHORT KERNEL_PROCESS_STOP        = 2;
static constexpr USHORT KERNEL_THREAD_START        = 3; // NOT yet empirically
    // verified on this machine (unlike CREATE/STOP/IMAGE_LOAD above) - the ID
    // and the "TThreadID"/"StartAddr" property names below are the commonly
    // documented ones for this provider's ThreadStart event; re-confirm via
    // `logman query providers "Microsoft-Windows-Kernel-Process"` plus a
    // throwaway diagnostic (same methodology as Phase 3) before relying on
    // them for anything beyond the interim visibility this adds.
static constexpr USHORT KERNEL_IMAGE_LOAD          = 5;

// Event IDs for Microsoft-Windows-Kernel-File. Empirically verified against
// this OS build's real manifest (see WINDOWS_COVERAGE_PLAN.md Phase 3 - IDs
// aren't documented per-version by Microsoft, so this was confirmed by
// tracing real write/rename/delete operations and reading back the actual
// EventDescriptor.Id + Keyword bits, not assumed from memory).
static constexpr USHORT KERNEL_FILE_CREATE         = 12;
static constexpr USHORT KERNEL_FILE_IO_READ        = 15;
static constexpr USHORT KERNEL_FILE_IO_WRITE       = 16;
static constexpr USHORT KERNEL_FILE_DELETE_PATH    = 26; // delete-via-SetInformation
static constexpr USHORT KERNEL_FILE_RENAME_PATH    = 27; // rename-via-SetInformation/SetLink

// Event IDs for Microsoft-Windows-Kernel-Registry. Also empirically verified
// (real event IDs aren't documented per-OS-build by Microsoft) by tracing
// real RegCreateKeyExW/RegSetValueExW/RegDeleteValueW/RegDeleteKeyW calls -
// see WINDOWS_COVERAGE_PLAN.md Phase 3.
static constexpr USHORT KERNEL_REGISTRY_CREATE_KEY  = 1;
static constexpr USHORT KERNEL_REGISTRY_OPEN_KEY    = 2;
static constexpr USHORT KERNEL_REGISTRY_SET_VALUE   = 5;

// Event ID for Microsoft-Windows-TaskScheduler, empirically verified by
// registering, running, and deleting a real scheduled task via schtasks.exe
// (see WINDOWS_COVERAGE_PLAN.md Phase 3): 106 fires with (TaskName,
// UserContext) on real task registration - the "persistence write" signal
// this phase asks for. 140 (fires around task run) and 325 (fires around
// task delete) were also observed but are deliberately not wired up here -
// out of scope for the "persistence write" detection category this phase
// targets, and there's no telemetry.h schema for them yet.
static constexpr USHORT TASK_SCHEDULER_TASK_REGISTERED = 106;

// Event IDs for Microsoft-Windows-Threat-Intelligence. NOT empirically
// verified on THIS machine's real manifest (unlike every other ID in this
// file, and unlike the KEYWORD names above which were - see the logman
// output referenced in WINDOWS_COVERAGE_PLAN.md Phase 4) - EnableTraceEx2
// against this provider still fails with ACCESS_DENIED here (needs
// Antimalware-PPL), so there's no way to trace a real event and read back
// its actual EventDescriptor.Id the way Phase 3's IDs were confirmed.
// These specific numbers come from cross-referencing two independent public
// manifest sources against each other (repnz/etw-providers-docs' Win10-17134
// XML dump - task name to numeric ID - and jdu2600/Windows10EtwEvents' TSV,
// which agree on IDs 1-8/11-14 and imply 9-10 by the same REMOTE/LOCAL
// pairing pattern) - a materially stronger basis than "commonly cited",
// since two independently-maintained sources corroborate each other, but
// still not a substitute for tracing a real event on this machine. An
// earlier version of this code had QUEUE_USER_APC/SET_CONTEXT_THREAD/
// WRITE_VM wrong (5/8/10) from an unverified single-source guess; fixed
// against the cross-referenced mapping below. Re-verify all five once PPL
// access exists, same as Phase 3's methodology.
static constexpr USHORT THREATINT_ALLOC_VM           = 1;  // VirtualAlloc(Ex), remote
static constexpr USHORT THREATINT_PROTECT_VM         = 2;  // VirtualProtect(Ex), remote
static constexpr USHORT THREATINT_QUEUE_USER_APC     = 4;  // QueueUserAPC, remote
static constexpr USHORT THREATINT_SET_CONTEXT_THREAD = 5;  // SetThreadContext, remote
static constexpr USHORT THREATINT_WRITE_VM           = 14; // WriteProcessMemory, remote

// Impersonation-state-change event IDs. Corroborated across two independent
// public sources (a dedicated research write-up and separate search results
// that agree with each other), and this machine's own `logman query
// providers` output confirms the corresponding KERNEL_THREATINT_KEYWORD_
// PROCESS_IMPERSONATION_UP/DOWN/REVERT keywords genuinely exist in this OS
// build's manifest (see WINDOWS_COVERAGE_PLAN.md Phase 4) - stronger footing
// than a single-source guess, but still not traced on this machine.
// Additionally unresolved: public research describes these events as gated
// by a per-process EPROCESS.Flags3 bit ("EnableProcessImpersonationLogging")
// - it's not yet established whether enabling this provider's keyword is
// sufficient to have that bit set for arbitrary processes, or whether
// something else (a different opt-in) is required. Don't assume this fires
// unconditionally the way the memory-op events above are assumed to once
// PPL access exists - that assumption itself needs empirical confirmation.
static constexpr USHORT THREATINT_IMPERSONATION_UP     = 33;
static constexpr USHORT THREATINT_IMPERSONATION_REVERT = 34;
static constexpr USHORT THREATINT_IMPERSONATION_DOWN   = 36;

// Event IDs for Microsoft-Windows-Kernel-Network. Empirically verified (same
// methodology as File/Registry above) by tracing a real TCP connect+accept
// and a real UDP send - see WINDOWS_COVERAGE_PLAN.md Phase 3. Notably, a
// plain listen() call fires NO event on this provider at all (confirmed by
// tracing with every keyword enabled) - Kernel-Network only observes actual
// packet/flow-level activity (connect/accept/disconnect/send), not passive
// socket-state changes, so there is deliberately no "Listen" ID here.
static constexpr USHORT KERNEL_NETWORK_TCP_CONNECT = 12;   // TcpIp/Connect
static constexpr USHORT KERNEL_NETWORK_TCP_ACCEPT  = 15;   // TcpIp/Accept
static constexpr USHORT KERNEL_NETWORK_UDP_SEND    = 42;   // UdpIp/Send

// Event ID for Microsoft-Windows-Crypto-DPAPI. Empirically verified on this
// machine (same methodology as Phase 3's Kernel-File/Registry/Network IDs
// above, plus a second isolated-fresh-process test specifically to rule out
// "first DPAPI call in this process" confounding the result) - see
// WINDOWS_COVERAGE_PLAN.md Phase 6 for the full diagnostic writeup. Fires for
// BOTH CryptProtectData and CryptUnprotectData, distinguished by the
// OperationType property ("SPCryptProtect"/"SPCryptUnprotect") - there is no
// separate per-operation event ID, both share this one.
static constexpr USHORT DPAPI_DEF_INFORMATION_EVENT_ID = 16385;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Extract MOTW (Mark of the Web) ZoneId
// ─────────────────────────────────────────────────────────────────────────────
static int32_t GetZoneIdentifier(const std::string& file_path) {
    std::string zone_path = file_path + ":Zone.Identifier";
    std::ifstream ads(zone_path);
    if (!ads.is_open()) return -1;

    std::string line;
    while (std::getline(ads, line)) {
        if (line.find("ZoneId=") != std::string::npos) {
            try {
                return std::stoi(line.substr(7));
            } catch (...) {
                return -1;
            }
        }
    }
    return -1;
}

// Fix 4's VerifyAuthenticodeSignature (real WinVerifyTrust chain validation,
// replacing the old path-string stub) now lives in authenticode.h/.cpp,
// shared with resource_identity.cpp's owner-signer allowlist check
// (WINDOWS_COVERAGE_PLAN.md Phase 5 / antitheft.md §4's identity_pin).

// ─────────────────────────────────────────────────────────────────────────────
// Helper: TDH property extraction
// ─────────────────────────────────────────────────────────────────────────────

// Fetch a single WCHAR* property value as a std::wstring.
static std::wstring TdhGetWStringProperty(PEVENT_RECORD event,
                                           PTRACE_EVENT_INFO info,
                                           const wchar_t* prop_name) {
    for (ULONG i = 0; i < info->PropertyCount; ++i) {
        const wchar_t* name = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);
        if (wcscmp(name, prop_name) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc = {};
            desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
            desc.ArrayIndex   = ULONG_MAX;

            ULONG buf_size = 0;
            TdhGetPropertySize(event, 0, nullptr, 1, &desc, &buf_size);
            if (buf_size == 0) return {};

            std::vector<BYTE> buf(buf_size);
            if (TdhGetProperty(event, 0, nullptr, 1, &desc,
                               buf_size, buf.data()) == ERROR_SUCCESS) {
                return std::wstring(reinterpret_cast<wchar_t*>(buf.data()));
            }
        }
    }
    return {};
}

// Fetch a ULONG property.
static ULONG TdhGetULongProperty(PEVENT_RECORD event,
                                  PTRACE_EVENT_INFO info,
                                  const wchar_t* prop_name,
                                  ULONG default_val = 0) {
    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONG value = default_val;
    ULONG buf_size = sizeof(value);
    TdhGetProperty(event, 0, nullptr, 1, &desc, buf_size,
                   reinterpret_cast<PBYTE>(&value));
    return value;
}

// Fetch a UInt64 property (e.g. ProcessSequenceNumber). TDH property-name
// lookup is case-sensitive against the provider manifest, so callers must
// pass the exact manifest spelling. `out_found` (if non-null) distinguishes
// "property missing on this OS build" from "value happens to be 0" - the
// latter is not a safe default for reuse-resistant identifiers.
static uint64_t TdhGetULongLongProperty(PEVENT_RECORD event,
                                         PTRACE_EVENT_INFO info,
                                         const wchar_t* prop_name,
                                         bool* out_found = nullptr) {
    (void)info;
    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONG buf_size = 0;
    if (TdhGetPropertySize(event, 0, nullptr, 1, &desc, &buf_size) != ERROR_SUCCESS
            || buf_size == 0) {
        if (out_found) *out_found = false;
        return 0;
    }

    std::vector<BYTE> buf(buf_size, 0);
    if (TdhGetProperty(event, 0, nullptr, 1, &desc, buf_size, buf.data())
            != ERROR_SUCCESS) {
        if (out_found) *out_found = false;
        return 0;
    }

    uint64_t value = 0;
    memcpy(&value, buf.data(), (std::min)(static_cast<size_t>(buf_size), sizeof(value)));
    if (out_found) *out_found = true;
    return value;
}

// Fetch a fixed-size binary property (e.g. a raw GUID) into out. Returns
// false (and leaves out untouched) unless the property's actual size on the
// wire exactly matches out_size - callers pass the size they know the
// property's manifest type to be (e.g. 16 for a GUID), so a mismatch means
// something about the assumption is wrong and this should not silently
// truncate/overrun.
static bool TdhGetRawBytesProperty(PEVENT_RECORD event, const wchar_t* prop_name,
                                    BYTE* out, ULONG out_size) {
    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONG buf_size = 0;
    if (TdhGetPropertySize(event, 0, nullptr, 1, &desc, &buf_size) != ERROR_SUCCESS
            || buf_size != out_size) {
        return false;
    }
    return TdhGetProperty(event, 0, nullptr, 1, &desc, buf_size, out) == ERROR_SUCCESS;
}

// Shared by Connect/Accept/UDP-send below - extracts an IPv4/IPv6 address
// property (a raw SOCKADDR-family binary blob, sized 4 or 16 bytes) as text.
static std::string TdhGetIPProperty(PEVENT_RECORD event, const wchar_t* prop_name) {
    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex = ULONG_MAX;
    ULONG addr_size = 0;
    TdhGetPropertySize(event, 0, nullptr, 1, &desc, &addr_size);
    if (addr_size < 4) return {};
    std::vector<BYTE> addr_buf(addr_size);
    if (TdhGetProperty(event, 0, nullptr, 1, &desc, addr_size, addr_buf.data()) != ERROR_SUCCESS)
        return {};
    char text[46] = {};
    if (addr_size == 4) {
        struct in_addr ia;
        memcpy(&ia, addr_buf.data(), 4);
        inet_ntop(AF_INET, &ia, text, sizeof(text));
    } else if (addr_size == 16) {
        struct in6_addr ia6;
        memcpy(&ia6, addr_buf.data(), 16);
        inet_ntop(AF_INET6, &ia6, text, sizeof(text));
    }
    return std::string(text);
}

// Kernel-Network's "dport"/"sport" properties are raw network-byte-order
// (big-endian) values - must go through ntohs, same as the pre-existing
// Connect handling already did.
static uint16_t TdhGetPortProperty(PEVENT_RECORD event, PTRACE_EVENT_INFO info,
                                    const wchar_t* prop_name) {
    return static_cast<uint16_t>(
        ntohs(static_cast<u_short>(TdhGetULongProperty(event, info, prop_name))));
}

// Narrow-string helper.
static std::string WstrToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                        &s[0], n, nullptr, nullptr);
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// EtwConsumer implementation
// ─────────────────────────────────────────────────────────────────────────────

EtwConsumer* EtwConsumer::instance_ = nullptr;
static ULONG s_sequence = 0;

// Kernel-File Write/Read events carry a FileObject + IOSize but no path;
// Rename/Delete carry FileObject too, though Rename/Delete also happen to
// carry the acted-on path directly via their own "FilePath" property (see
// below) so this cache is only strictly needed to resolve Write's path and
// Rename's *source* path (FilePath on a rename event is the destination).
// Keyed on the FileObject kernel pointer value, populated from FileCreate.
// Simplification, stated plainly rather than implied-solved (matches
// core/CLAUDE.md's "state explicitly" ethic): Close/Cleanup events (10/11)
// don't carry FileObject in their own property set on this OS build, only
// FileKey+FileName, so this cache can't be precisely evicted per-handle-close
// and instead just caps its total size and clears outright when the cap is
// hit. For detection-only telemetry (not enforcement) this is an acceptable
// bound - worst case is a stale/wrong path attributed to a rare FileObject
// pointer reuse, not a security decision.
static std::unordered_map<uint64_t, std::string> s_file_object_paths;
static constexpr size_t kFileObjectPathCacheCap = 8192;

static void CacheFileObjectPath(uint64_t file_object, const std::string& path) {
    if (file_object == 0 || path.empty()) return;
    if (s_file_object_paths.size() >= kFileObjectPathCacheCap) {
        s_file_object_paths.clear();
    }
    s_file_object_paths[file_object] = path;
}

static std::string LookupFileObjectPath(uint64_t file_object) {
    auto it = s_file_object_paths.find(file_object);
    return it != s_file_object_paths.end() ? it->second : std::string();
}

// Same pattern as the FileObject cache above, for the registry side: a
// SetValueKey event's own "KeyName" property is empty on this OS build - the
// full key path only appears on the preceding CreateKey/OpenKey event, tied
// together by KeyObject. Same stated simplification: no reliable per-handle
// eviction signal (CloseKey's own property set doesn't carry KeyObject on
// this OS build either), so this just caps and clears rather than a true LRU.
static std::unordered_map<uint64_t, std::string> s_key_object_paths;
static constexpr size_t kKeyObjectPathCacheCap = 8192;

static void CacheKeyObjectPath(uint64_t key_object, const std::string& path) {
    if (key_object == 0 || path.empty()) return;
    if (s_key_object_paths.size() >= kKeyObjectPathCacheCap) {
        s_key_object_paths.clear();
    }
    s_key_object_paths[key_object] = path;
}

static std::string LookupKeyObjectPath(uint64_t key_object) {
    auto it = s_key_object_paths.find(key_object);
    return it != s_key_object_paths.end() ? it->second : std::string();
}

// Best-effort human-readable summary of a registry value's type - full raw
// value-data decoding (the "CapturedData" TDH property) is a length-prefixed
// binary property that the simple by-name PROPERTY_DATA_DESCRIPTOR lookup
// used elsewhere in this file can't reliably size/fetch; stated explicitly
// as a known limitation rather than attempting a fragile manual UserData
// offset walk. This gives the value's type + size, not its actual bytes.
static std::string RegistryTypeName(uint64_t reg_type) {
    switch (reg_type) {
        case 1: return "REG_SZ";
        case 2: return "REG_EXPAND_SZ";
        case 3: return "REG_BINARY";
        case 4: return "REG_DWORD";
        case 7: return "REG_MULTI_SZ";
        case 11: return "REG_QWORD";
        default: return "REG_TYPE_" + std::to_string(reg_type);
    }
}

EtwConsumer::EtwConsumer()
    : session_handle_(0), trace_handle_(0),
      thread_handle_(NULL), running_(false) {
    instance_ = this;
}

EtwConsumer::~EtwConsumer() {
    Stop();
    instance_ = nullptr;
}

// Fix 3a: Open a real real-time ETW session and enable kernel providers.
bool EtwConsumer::Initialize() {
    static const WCHAR* SESSION_NAME = L"KinnectorEtwSession";

    // Allocate EVENT_TRACE_PROPERTIES (needs extra space for the session name)
    const ULONG name_len = static_cast<ULONG>(
        (wcslen(SESSION_NAME) + 1) * sizeof(WCHAR));
    const ULONG props_size = sizeof(EVENT_TRACE_PROPERTIES) + name_len;

    std::vector<BYTE> props_buf(props_size, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.data());

    props->Wnode.BufferSize  = props_size;
    props->Wnode.Flags       = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode       = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer        = 1; // seconds
    props->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES);

    // Stop any stale session with the same name first. Explicit *W variant:
    // the ControlTrace/StartTrace TCHAR macros resolve to the ANSI overload
    // unless the project defines UNICODE, but SESSION_NAME is a wide literal.
    ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    // Reset the buffer (ControlTrace may have modified it)
    std::fill(props_buf.begin(), props_buf.end(), 0);
    props->Wnode.BufferSize  = props_size;
    props->Wnode.Flags       = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode       = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer        = 1;
    props->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&session_handle_, SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] StartTrace failed: " << status << "\n";
        return false;
    }

    // Enable Microsoft-Windows-Kernel-Process (ProcessCreate + ImageLoad)
    ENABLE_TRACE_PARAMETERS etp_proc = {};
    etp_proc.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &KernelProcessGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x10 |  // WINEVENT_KEYWORD_PROCESS
        0x20 |  // WINEVENT_KEYWORD_IMAGE
        0x40,   // WINEVENT_KEYWORD_THREAD - not yet empirically confirmed on
                // this machine like the two bits above are, see the
                // KERNEL_THREAD_START comment; needed for cross-process
                // thread-creation visibility (see ProcessEvent below).
        0, 0, &etp_proc);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-Process) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Kernel-File. Keyword values verified against
    // this OS build's real manifest via `logman query providers
    // "Microsoft-Windows-Kernel-File"` (see WINDOWS_COVERAGE_PLAN.md Phase 3)
    // - a prior version of this code enabled 0x10, believing it was the read
    // keyword; 0x10 is actually KERNEL_FILE_KEYWORD_FILENAME, and none of the
    // Read/Write/Delete/Rename events carry that bit in their own keyword
    // mask, so FileRead silently never fired under the old mask. Real bits:
    ENABLE_TRACE_PARAMETERS etp_file = {};
    etp_file.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &KernelFileGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x80  |  // KERNEL_FILE_KEYWORD_CREATE
        0x100 |  // KERNEL_FILE_KEYWORD_READ
        0x200 |  // KERNEL_FILE_KEYWORD_WRITE
        0x400 |  // KERNEL_FILE_KEYWORD_DELETE_PATH
        0x800,   // KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH
        0, 0, &etp_file);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-File) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Kernel-Network. Keyword verified via `logman
    // query providers "Microsoft-Windows-Kernel-Network"` plus a real traced
    // connect/accept/UDP-send (see WINDOWS_COVERAGE_PLAN.md Phase 3) - the
    // prior mask (0x01, believed to be "WINEVENT_KEYWORD_NETWORK_TCPIP")
    // isn't even a keyword this provider defines; every real Connect/
    // Accept/UDP-send event observed carried only IPV4(0x10) or IPV6(0x20),
    // so NetworkConnect telemetry had likely never actually fired either -
    // same bug class as the Kernel-File keyword fix above.
    ENABLE_TRACE_PARAMETERS etp_net = {};
    etp_net.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &KernelNetworkGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x10 |  // KERNEL_NETWORK_KEYWORD_IPV4
        0x20,   // KERNEL_NETWORK_KEYWORD_IPV6
        0, 0, &etp_net);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-Network) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Kernel-Registry (CreateKey + OpenKey, to seed
    // the KeyObject->path correlation cache, + SetValueKey for the actual
    // write telemetry). Keyword values verified via `logman query providers`
    // (see WINDOWS_COVERAGE_PLAN.md Phase 3).
    ENABLE_TRACE_PARAMETERS etp_reg = {};
    etp_reg.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &KernelRegistryGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x1000 |  // CreateKey
        0x2000 |  // OpenKey
        0x100,    // SetValueKey
        0, 0, &etp_reg);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-Registry) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-TaskScheduler's Operational channel keyword
    // specifically (0x8000000000000000, confirmed via `logman query
    // providers`) rather than all keywords, to avoid the Debug/Diagnostic/
    // Maintenance channels' noise - event 106 (TaskRegistered) lives on
    // Operational.
    ENABLE_TRACE_PARAMETERS etp_task = {};
    etp_task.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &TaskSchedulerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x8000000000000000ULL,  // Microsoft-Windows-TaskScheduler/Operational
        0, 0, &etp_task);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (TaskScheduler) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Crypto-DPAPI. Keyword mask verified empirically
    // (see WINDOWS_COVERAGE_PLAN.md Phase 6): the semantically-expected task
    // keywords (ETW_TASK_DATAPROTECTION_OPERATION 0x4 / MASTERKEY_OPERATION
    // 0x2 / CREDKEY_OPERATION 0x8, per `logman query providers`) produced NO
    // events at all across repeated Protect/Unprotect calls - only the Debug
    // channel keyword (0x2000000000000000) combined with the
    // ETW_TASK_DEF_INFORMATION task bit (0x40) does. Narrowed down from an
    // initial "enable every keyword" probe to confirm this exact minimal mask
    // is what's required, not just that a superset works.
    ENABLE_TRACE_PARAMETERS etp_dpapi = {};
    etp_dpapi.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &DpapiGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x2000000000000000ULL |  // Microsoft-Windows-Crypto-DPAPI/Debug channel
        0x40,                    // ETW_TASK_DEF_INFORMATION
        0, 0, &etp_dpapi);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Crypto-DPAPI) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Threat-Intelligence (ETW-TI). Expected to fail
    // with ACCESS_DENIED on an ordinary elevated session - this requires the
    // calling process to run as Antimalware-PPL (see WINDOWS_COVERAGE_PLAN.md
    // Phase 4). Left enabled here (failure just logs, same as every other
    // provider above) so this activates automatically once the process is
    // actually running under PPL, with no further code change needed.
    ENABLE_TRACE_PARAMETERS etp_ti = {};
    etp_ti.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &ThreatIntelGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0, &etp_ti);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Threat-Intelligence) failed: "
                  << status << " (expected ACCESS_DENIED without "
                     "Antimalware-PPL - see WINDOWS_COVERAGE_PLAN.md Phase 4)\n";
    }

    std::cout << "[ETW] Session started, providers enabled.\n";
    return true;
}

// Fix 3b: Route real parsed events to the callback.
void WINAPI EtwConsumer::EventRecordCallback(PEVENT_RECORD event) {
    if (instance_) {
        instance_->ProcessEvent(event);
    }
}

void EtwConsumer::ProcessEvent(PEVENT_RECORD event) {
    if (!callback_) return;

    // Use TDH to get schema info for property extraction
    ULONG info_size = 0;
    TdhGetEventInformation(event, 0, nullptr, nullptr, &info_size);
    if (info_size == 0) return;

    std::vector<BYTE> info_buf(info_size);
    auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(info_buf.data());
    if (TdhGetEventInformation(event, 0, nullptr, info, &info_size)
            != ERROR_SUCCESS) return;

    TelemetryEvent out = {};
    out.header.sequence_number = ++s_sequence;
    out.header.timestamp_ns    = event->EventHeader.TimeStamp.QuadPart * 100ULL;
    out.header.pid             = event->EventHeader.ProcessId;
    out.header.source          = TelemetrySource::ETW;

    const USHORT event_id = event->EventHeader.EventDescriptor.Id;
    bool should_emit = false;

    // ── Microsoft-Windows-Kernel-Process ─────────────────────────────────────
    if (IsEqualGUID(event->EventHeader.ProviderId, KernelProcessGuid)) {

        if (event_id == KERNEL_PROCESS_CREATE) {
            out.header.event_type = EventType::ProcessCreate;
            auto image_path = TdhGetWStringProperty(event, info, L"ImageName");
            auto cmd_line   = TdhGetWStringProperty(event, info, L"CommandLine");
            // Property names are case-sensitive against the provider manifest:
            // it's "ProcessID"/"ParentProcessID" (capital ID), not "...Id".
            auto child_pid  = TdhGetULongProperty(event, info, L"ProcessID");
            auto parent_pid = TdhGetULongProperty(event, info, L"ParentProcessID");

            bool child_seq_found = false, parent_seq_found = false;
            uint64_t child_seq = TdhGetULongLongProperty(
                event, info, L"ProcessSequenceNumber", &child_seq_found);
            uint64_t parent_seq = TdhGetULongLongProperty(
                event, info, L"ParentProcessSequenceNumber", &parent_seq_found);
            if (!child_seq_found || !parent_seq_found) {
                static bool s_warned_missing_sequence_number = false;
                if (!s_warned_missing_sequence_number) {
                    std::cerr << "[ETW] Warning: ProcessSequenceNumber/"
                                 "ParentProcessSequenceNumber not found on this "
                                 "OS build; process lineage falls back to "
                                 "PID-only (reuse-vulnerable) keying.\n";
                    s_warned_missing_sequence_number = true;
                }
            }

            std::string path_utf8 = WstrToUtf8(image_path);
            std::string cmd_utf8  = WstrToUtf8(cmd_line);

            strncpy_s(out.details.process_create.child_image_path,
                      path_utf8.c_str(), _TRUNCATE);
            strncpy_s(out.details.process_create.child_command_line,
                      cmd_utf8.c_str(), _TRUNCATE);
            out.details.process_create.child_pid      = child_pid;
            out.details.process_create.real_parent_pid = parent_pid;
            out.details.process_create.child_sequence_number  = child_seq;
            out.details.process_create.parent_sequence_number = parent_seq;
            should_emit = true;

        } else if (event_id == KERNEL_THREAD_START) {
            // Pure observation: compare who *called* the thread-create API
            // (EventHeader.ProcessId, the caller) against which process the
            // new thread actually belongs to (the "ProcessID" property, the
            // owner). No memory read, no handle operation, no interaction
            // with either process - just recording the two IDs to build an
            // accurate process/thread ownership tree. Only emitted when they
            // differ (cross-process/"remote" thread creation) - matching
            // in-process thread creation is normal, high-volume churn with
            // no lineage-tree value, so it's deliberately not forwarded.
            uint32_t owner_pid = TdhGetULongProperty(event, info, L"ProcessID");
            uint32_t caller_pid = event->EventHeader.ProcessId;
            if (owner_pid != 0 && owner_pid != caller_pid) {
                out.header.event_type = EventType::ThreadContextAccess;
                out.details.thread_context_access.target_pid = owner_pid;
                out.details.thread_context_access.target_tid =
                    TdhGetULongProperty(event, info, L"TThreadID");
                out.details.thread_context_access.start_address =
                    TdhGetULongLongProperty(event, info, L"StartAddr");
                strncpy_s(out.details.thread_context_access.operation,
                          "RemoteThreadCreate", _TRUNCATE);
                should_emit = true;
            }

        } else if (event_id == KERNEL_PROCESS_STOP) {
            out.header.event_type = EventType::ProcessStop;
            auto exit_code = TdhGetULongProperty(event, info, L"ExitCode");
            out.details.process_stop.exit_code = static_cast<int32_t>(exit_code);
            should_emit = true;

        } else if (event_id == KERNEL_IMAGE_LOAD) {
            out.header.event_type = EventType::ImageLoad;
            auto image_path = TdhGetWStringProperty(event, info, L"ImageName");
            std::string path_utf8 = WstrToUtf8(image_path);
            strncpy_s(out.details.image_load.module_path,
                      path_utf8.c_str(), _TRUNCATE);
            // Fix 4: real Authenticode verification
            out.details.image_load.is_signed = static_cast<uint8_t>(
                VerifyAuthenticodeSignature(
                    image_path,
                    out.details.image_load.signer_subject,
                    sizeof(out.details.image_load.signer_subject)));
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-Kernel-File ────────────────────────────────────────
    else if (IsEqualGUID(event->EventHeader.ProviderId, KernelFileGuid)) {

        if (event_id == KERNEL_FILE_CREATE) {
            out.header.event_type = EventType::FileCreate;
            auto file_path = TdhGetWStringProperty(event, info, L"FileName");
            std::string path_utf8 = WstrToUtf8(file_path);
            strncpy_s(out.details.file_create.file_path,
                      path_utf8.c_str(), _TRUNCATE);
            out.details.file_create.zone_id = GetZoneIdentifier(path_utf8);
            bool file_object_found = false;
            uint64_t file_object = TdhGetULongLongProperty(
                event, info, L"FileObject", &file_object_found);
            if (file_object_found) CacheFileObjectPath(file_object, path_utf8);
            should_emit = true;

        } else if (event_id == KERNEL_FILE_IO_READ) {
            out.header.event_type = EventType::FileRead;
            auto file_path = TdhGetWStringProperty(event, info, L"FileName");
            std::string path_utf8 = WstrToUtf8(file_path);
            strncpy_s(out.details.file_read.file_path,
                      path_utf8.c_str(), _TRUNCATE);
            out.details.file_read.zone_id =
                GetZoneIdentifier(path_utf8);
            // Property name is case-sensitive against the manifest - it's
            // "IOSize" (capital O), not "IoSize"; this previously read as an
            // always-0 default, same bug class as Phase 2's ProcessId fix.
            out.details.file_read.bytes_requested =
                TdhGetULongProperty(event, info, L"IOSize");
            should_emit = true;

        } else if (event_id == KERNEL_FILE_IO_WRITE) {
            out.header.event_type = EventType::FileWrite;
            uint64_t file_object = TdhGetULongLongProperty(event, info, L"FileObject");
            std::string path = LookupFileObjectPath(file_object);
            strncpy_s(out.details.file_write.file_path,
                      path.c_str(), _TRUNCATE);
            out.details.file_write.bytes_written =
                TdhGetULongProperty(event, info, L"IOSize");
            should_emit = true;

        } else if (event_id == KERNEL_FILE_RENAME_PATH) {
            out.header.event_type = EventType::FileRename;
            // FilePath on this event is the destination/new path (empirically
            // verified - see WINDOWS_COVERAGE_PLAN.md Phase 3); the source
            // path is resolved from the FileObject cache seeded at Create.
            auto dest_path = TdhGetWStringProperty(event, info, L"FilePath");
            std::string dest_utf8 = WstrToUtf8(dest_path);
            uint64_t file_object = TdhGetULongLongProperty(event, info, L"FileObject");
            std::string src = LookupFileObjectPath(file_object);
            strncpy_s(out.details.file_rename.source_path,
                      src.c_str(), _TRUNCATE);
            strncpy_s(out.details.file_rename.destination_path,
                      dest_utf8.c_str(), _TRUNCATE);
            // The renamed file keeps the same FileObject going forward -
            // update the cache so a later Write/further Rename against the
            // same handle resolves to the new path, not the stale one.
            if (file_object != 0 && !dest_utf8.empty())
                CacheFileObjectPath(file_object, dest_utf8);
            should_emit = true;

        } else if (event_id == KERNEL_FILE_DELETE_PATH) {
            out.header.event_type = EventType::FileDelete;
            // FilePath on this event is the deleted file's own full path
            // directly (empirically verified) - no FileObject cache needed.
            auto file_path = TdhGetWStringProperty(event, info, L"FilePath");
            std::string path_utf8 = WstrToUtf8(file_path);
            strncpy_s(out.details.file_delete.file_path,
                      path_utf8.c_str(), _TRUNCATE);
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-Kernel-Network ─────────────────────────────────────
    else if (IsEqualGUID(event->EventHeader.ProviderId, KernelNetworkGuid)) {

        if (event_id == KERNEL_NETWORK_TCP_CONNECT) {
            out.header.event_type = EventType::NetworkConnect;
            std::string daddr = TdhGetIPProperty(event, L"daddr");
            strncpy_s(out.details.network_connect.destination_ip,
                      daddr.c_str(), _TRUNCATE);
            out.details.network_connect.destination_port =
                TdhGetPortProperty(event, info, L"dport");
            strncpy_s(out.details.network_connect.protocol, "TCP", _TRUNCATE);
            should_emit = true;

        } else if (event_id == KERNEL_NETWORK_UDP_SEND) {
            // Reuses NetworkConnectDetails - its protocol[8] field already
            // anticipates "TCP, UDP" per its own comment in telemetry.h, and
            // UDP send/connect share the same daddr/dport shape.
            out.header.event_type = EventType::NetworkConnect;
            std::string daddr = TdhGetIPProperty(event, L"daddr");
            strncpy_s(out.details.network_connect.destination_ip,
                      daddr.c_str(), _TRUNCATE);
            out.details.network_connect.destination_port =
                TdhGetPortProperty(event, info, L"dport");
            strncpy_s(out.details.network_connect.protocol, "UDP", _TRUNCATE);
            should_emit = true;

        } else if (event_id == KERNEL_NETWORK_TCP_ACCEPT) {
            out.header.event_type = EventType::NetworkAccept;
            // Empirically verified (see WINDOWS_COVERAGE_PLAN.md Phase 3):
            // on the Accept event, saddr/sport are the local listening
            // socket's own address (this machine), daddr/dport are the
            // remote peer that connected in - opposite emphasis from
            // Connect, where daddr/dport are the thing being connected to.
            std::string daddr = TdhGetIPProperty(event, L"daddr");
            strncpy_s(out.details.network_accept.remote_ip,
                      daddr.c_str(), _TRUNCATE);
            out.details.network_accept.remote_port =
                TdhGetPortProperty(event, info, L"dport");
            out.details.network_accept.local_port =
                TdhGetPortProperty(event, info, L"sport");
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-Kernel-Registry ────────────────────────────────────
    else if (IsEqualGUID(event->EventHeader.ProviderId, KernelRegistryGuid)) {

        if (event_id == KERNEL_REGISTRY_CREATE_KEY || event_id == KERNEL_REGISTRY_OPEN_KEY) {
            // Not emitted as their own telemetry event (no CreateKey/OpenKey
            // EventType exists in telemetry.h today - see Phase 3 notes on
            // what's still open) - only used to seed the KeyObject->path
            // cache that SetValueKey below depends on for its key_path.
            auto rel_name = TdhGetWStringProperty(event, info, L"RelativeName");
            std::string path_utf8 = WstrToUtf8(rel_name);
            bool key_object_found = false;
            uint64_t key_object = TdhGetULongLongProperty(
                event, info, L"KeyObject", &key_object_found);
            if (key_object_found) CacheKeyObjectPath(key_object, path_utf8);

        } else if (event_id == KERNEL_REGISTRY_SET_VALUE) {
            out.header.event_type = EventType::RegistryWrite;
            uint64_t key_object = TdhGetULongLongProperty(event, info, L"KeyObject");
            std::string key_path = LookupKeyObjectPath(key_object);
            strncpy_s(out.details.registry_write.key_path,
                      key_path.c_str(), _TRUNCATE);
            auto value_name = TdhGetWStringProperty(event, info, L"ValueName");
            strncpy_s(out.details.registry_write.value_name,
                      WstrToUtf8(value_name).c_str(), _TRUNCATE);
            uint64_t reg_type = TdhGetULongLongProperty(event, info, L"Type");
            uint64_t data_size = TdhGetULongLongProperty(event, info, L"DataSize");
            std::string summary = RegistryTypeName(reg_type) + " (" +
                                   std::to_string(data_size) + " bytes)";
            strncpy_s(out.details.registry_write.value_data,
                      summary.c_str(), _TRUNCATE);
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-TaskScheduler ──────────────────────────────────────
    else if (IsEqualGUID(event->EventHeader.ProviderId, TaskSchedulerGuid)) {

        if (event_id == TASK_SCHEDULER_TASK_REGISTERED) {
            out.header.event_type = EventType::TaskRegistered;
            auto task_name = TdhGetWStringProperty(event, info, L"TaskName");
            auto user_context = TdhGetWStringProperty(event, info, L"UserContext");
            strncpy_s(out.details.task_registered.task_name,
                      WstrToUtf8(task_name).c_str(), _TRUNCATE);
            strncpy_s(out.details.task_registered.user_context,
                      WstrToUtf8(user_context).c_str(), _TRUNCATE);
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-Threat-Intelligence ────────────────────────────────
    // Property names below are unverified placeholders - see the ID-block
    // comment above. Pure data capture (pid/address/size), no interpretation.
    else if (IsEqualGUID(event->EventHeader.ProviderId, ThreatIntelGuid)) {

        if (event_id == THREATINT_ALLOC_VM || event_id == THREATINT_PROTECT_VM ||
            event_id == THREATINT_WRITE_VM) {
            out.header.event_type = EventType::CrossProcessMemoryAccess;
            out.details.cross_process_memory_access.target_pid =
                TdhGetULongProperty(event, info, L"TargetProcessId");
            out.details.cross_process_memory_access.address =
                TdhGetULongLongProperty(event, info, L"BaseAddress");
            out.details.cross_process_memory_access.size =
                TdhGetULongLongProperty(event, info, L"RegionSize");
            const char* op = event_id == THREATINT_ALLOC_VM   ? "VirtualAlloc"
                            : event_id == THREATINT_PROTECT_VM ? "VirtualProtect"
                                                                : "WriteProcessMemory";
            strncpy_s(out.details.cross_process_memory_access.operation,
                      op, _TRUNCATE);
            auto protection = TdhGetULongProperty(event, info, L"Protection");
            strncpy_s(out.details.cross_process_memory_access.protection,
                      std::to_string(protection).c_str(), _TRUNCATE);
            should_emit = true;

        } else if (event_id == THREATINT_SET_CONTEXT_THREAD ||
                   event_id == THREATINT_QUEUE_USER_APC) {
            out.header.event_type = EventType::ThreadContextAccess;
            out.details.thread_context_access.target_pid =
                TdhGetULongProperty(event, info, L"TargetProcessId");
            out.details.thread_context_access.target_tid =
                TdhGetULongProperty(event, info, L"TargetThreadId");
            out.details.thread_context_access.start_address =
                TdhGetULongLongProperty(event, info, L"StartAddress");
            const char* op = event_id == THREATINT_SET_CONTEXT_THREAD
                                  ? "SetThreadContext" : "QueueUserAPC";
            strncpy_s(out.details.thread_context_access.operation,
                      op, _TRUNCATE);
            should_emit = true;

        } else if (event_id == THREATINT_IMPERSONATION_UP ||
                   event_id == THREATINT_IMPERSONATION_DOWN ||
                   event_id == THREATINT_IMPERSONATION_REVERT) {
            // Pure data capture: who changed effective identity, in which
            // direction, and what their token looked like immediately
            // before. No assessment of whether the change is expected.
            out.header.event_type = EventType::ImpersonationChange;
            out.details.impersonation_change.calling_pid =
                TdhGetULongProperty(event, info, L"CallingProcessId");
            out.details.impersonation_change.calling_tid =
                TdhGetULongProperty(event, info, L"CallingThreadId");
            const char* dir = event_id == THREATINT_IMPERSONATION_UP ? "UP"
                             : event_id == THREATINT_IMPERSONATION_DOWN ? "DOWN"
                                                                         : "REVERT";
            strncpy_s(out.details.impersonation_change.direction,
                      dir, _TRUNCATE);
            auto prev_user = TdhGetWStringProperty(event, info, L"PreviousTokenUser");
            strncpy_s(out.details.impersonation_change.previous_token_user,
                      WstrToUtf8(prev_user).c_str(), _TRUNCATE);
            auto prev_integrity = TdhGetULongProperty(event, info, L"PreviousTokenIntegrityLevel");
            strncpy_s(out.details.impersonation_change.previous_token_integrity,
                      std::to_string(prev_integrity).c_str(), _TRUNCATE);
            out.details.impersonation_change.previous_token_elevated =
                static_cast<uint8_t>(TdhGetULongProperty(event, info, L"PreviousTokenElevation"));
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-Crypto-DPAPI ───────────────────────────────────────
    else if (IsEqualGUID(event->EventHeader.ProviderId, DpapiGuid)) {

        if (event_id == DPAPI_DEF_INFORMATION_EVENT_ID) {
            out.header.event_type = EventType::DpapiOperation;

            auto operation_type   = TdhGetWStringProperty(event, info, L"OperationType");
            auto data_description = TdhGetWStringProperty(event, info, L"DataDescription");
            strncpy_s(out.details.dpapi_operation.operation_type,
                      WstrToUtf8(operation_type).c_str(), _TRUNCATE);
            strncpy_s(out.details.dpapi_operation.data_description,
                      WstrToUtf8(data_description).c_str(), _TRUNCATE);

            if (!TdhGetRawBytesProperty(event, L"MasterKeyGUID",
                                         out.details.dpapi_operation.master_key_guid,
                                         sizeof(out.details.dpapi_operation.master_key_guid))) {
                memset(out.details.dpapi_operation.master_key_guid, 0,
                       sizeof(out.details.dpapi_operation.master_key_guid));
            }

            out.details.dpapi_operation.flags = TdhGetULongProperty(event, info, L"Flags");
            out.details.dpapi_operation.protection_flags = TdhGetULongProperty(event, info, L"ProtectionFlags");
            out.details.dpapi_operation.return_value = static_cast<int32_t>(
                TdhGetULongProperty(event, info, L"ReturnValue"));
            out.details.dpapi_operation.plaintext_data_size =
                TdhGetULongProperty(event, info, L"PlainTextDataSize");
            out.details.dpapi_operation.caller_process_start_key =
                TdhGetULongLongProperty(event, info, L"CallerProcessStartKey");

            const ULONG caller_pid = TdhGetULongProperty(event, info, L"CallerProcessID");
            out.details.dpapi_operation.caller_pid = caller_pid;
            out.details.dpapi_operation.caller_process_creation_time =
                TdhGetULongLongProperty(event, info, L"CallerProcessCreationTime");

            // DELIBERATE deviation from every other event type in this file:
            // event->EventHeader.ProcessId for this provider is always
            // lsass.exe (DPAPI master-key operations are carried out there
            // on the caller's behalf, confirmed empirically - see
            // telemetry.h's DpapiOperationDetails comment and
            // WINDOWS_COVERAGE_PLAN.md Phase 6), so leaving header.pid as
            // the default out.header.pid = event->EventHeader.ProcessId
            // (set earlier in this function) would misattribute 100% of
            // these events to lsass.exe. Override with the real caller.
            out.header.pid = caller_pid;
            should_emit = true;
        }
    }

    if (should_emit) {
        callback_(out);
    }
}

// Fix 3c: TraceThread now calls ProcessTrace (no longer a stub).
static DWORD WINAPI TraceThread(LPVOID param) {
    auto* self = static_cast<EtwConsumer*>(param);
    static const WCHAR* SESSION_NAME = L"KinnectorEtwSession";

    EVENT_TRACE_LOGFILEW log = {};
    log.LoggerName          = const_cast<LPWSTR>(SESSION_NAME);
    log.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                              PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EtwConsumer::EventRecordCallback;

    TRACEHANDLE th = OpenTraceW(&log);
    if (th == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[ETW] OpenTrace failed: " << GetLastError() << "\n";
        return 1;
    }

    // Blocks until CloseTrace() is called from Stop()
    ULONG status = ProcessTrace(&th, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        std::cerr << "[ETW] ProcessTrace exited with: " << status << "\n";
    }

    CloseTrace(th);
    return 0;
}

bool EtwConsumer::Start() {
    running_ = true;
    thread_handle_ = CreateThread(NULL, 0, TraceThread, this, 0, NULL);
    if (!thread_handle_) {
        std::cerr << "[ETW] CreateThread failed: " << GetLastError() << "\n";
        return false;
    }
    return true;
}

void EtwConsumer::Stop() {
    running_ = false;
    if (session_handle_) {
        static const ULONG props_size =
            sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR);
        std::vector<BYTE> buf(props_size, 0);
        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
        props->Wnode.BufferSize = props_size;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(session_handle_, nullptr, props,
                      EVENT_TRACE_CONTROL_STOP);
        session_handle_ = 0;
    }
    if (thread_handle_) {
        WaitForSingleObject(thread_handle_, 5000);
        CloseHandle(thread_handle_);
        thread_handle_ = NULL;
    }
}

void EtwConsumer::SetEventCallback(EventCallback cb) {
    callback_ = cb;
}

} // namespace kinnector::windows
