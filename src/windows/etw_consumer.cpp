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
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
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

// Event IDs for Microsoft-Windows-Kernel-Process
static constexpr USHORT KERNEL_PROCESS_CREATE     = 1;
static constexpr USHORT KERNEL_PROCESS_STOP        = 2;
static constexpr USHORT KERNEL_IMAGE_LOAD          = 5;

// Event IDs for Microsoft-Windows-Kernel-File
static constexpr USHORT KERNEL_FILE_CREATE         = 12;
static constexpr USHORT KERNEL_FILE_IO_READ        = 15;

// Event IDs for Microsoft-Windows-Kernel-Network (TcpIp)
static constexpr USHORT KERNEL_NETWORK_TCP_CONNECT = 12;   // TcpIp/Connect

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

// ─────────────────────────────────────────────────────────────────────────────
// Fix 4: VerifyAuthenticodeSignature — real WinVerifyTrust chain validation.
//
// Previously this was a path-string stub (checked for "Windows\System32").
// Now it calls WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2 and
// extracts the leaf signer subject via CryptQueryObject / CertGetNameString.
// ─────────────────────────────────────────────────────────────────────────────
static bool VerifyAuthenticodeSignature(const std::wstring& wpath,
                                         char* out_signer, size_t max_len) {
    if (out_signer && max_len > 0) out_signer[0] = '\0';

    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = wpath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = {};
    wd.cbStruct          = sizeof(WINTRUST_DATA);
    wd.dwUIChoice        = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   // offline environments
    wd.dwUnionChoice     = WTD_CHOICE_FILE;
    wd.pFile             = &file_info;
    wd.dwStateAction     = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags       = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE),
                                 &action, &wd);

    // Extract signer subject from the context before closing
    if (result == ERROR_SUCCESS && out_signer && max_len > 0 && wd.hWVTStateData) {
        CRYPT_PROVIDER_DATA* prov_data =
            reinterpret_cast<CRYPT_PROVIDER_DATA*>(wd.hWVTStateData);
        if (prov_data && prov_data->csSigners > 0 &&
            prov_data->pasSigners && prov_data->pasSigners[0].pasCertChain) {
            PCCERT_CONTEXT cert =
                prov_data->pasSigners[0].pasCertChain[0].pCert;
            if (cert) {
                CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                   0, nullptr, out_signer,
                                   static_cast<DWORD>(max_len));
            }
        }
    }

    // Always close the state to avoid leaks
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    return result == ERROR_SUCCESS;
}

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

    // Stop any stale session with the same name first
    ControlTrace(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    // Reset the buffer (ControlTrace may have modified it)
    std::fill(props_buf.begin(), props_buf.end(), 0);
    props->Wnode.BufferSize  = props_size;
    props->Wnode.Flags       = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode       = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer        = 1;
    props->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTrace(&session_handle_, SESSION_NAME, props);
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
        0x20,   // WINEVENT_KEYWORD_IMAGE
        0, 0, &etp_proc);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-Process) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Kernel-File (FileCreate + FileRead)
    ENABLE_TRACE_PARAMETERS etp_file = {};
    etp_file.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &KernelFileGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x80 |  // WINEVENT_KEYWORD_FILEIO_CREATE
        0x10,   // WINEVENT_KEYWORD_FILEIO_READ
        0, 0, &etp_file);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-File) failed: " << status << "\n";
    }

    // Enable Microsoft-Windows-Kernel-Network (TCP connect)
    ENABLE_TRACE_PARAMETERS etp_net = {};
    etp_net.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        session_handle_,
        &KernelNetworkGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x01,   // WINEVENT_KEYWORD_NETWORK_TCPIP
        0, 0, &etp_net);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 (Kernel-Network) failed: " << status << "\n";
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
            auto child_pid  = TdhGetULongProperty(event, info, L"ProcessId");
            auto parent_pid = TdhGetULongProperty(event, info, L"ParentProcessId");

            std::string path_utf8 = WstrToUtf8(image_path);
            std::string cmd_utf8  = WstrToUtf8(cmd_line);

            strncpy_s(out.details.process_create.child_image_path,
                      path_utf8.c_str(), _TRUNCATE);
            strncpy_s(out.details.process_create.child_command_line,
                      cmd_utf8.c_str(), _TRUNCATE);
            out.details.process_create.child_pid      = child_pid;
            out.details.process_create.real_parent_pid = parent_pid;
            should_emit = true;

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
            should_emit = true;

        } else if (event_id == KERNEL_FILE_IO_READ) {
            out.header.event_type = EventType::FileRead;
            auto file_path = TdhGetWStringProperty(event, info, L"FileName");
            std::string path_utf8 = WstrToUtf8(file_path);
            strncpy_s(out.details.file_read.file_path,
                      path_utf8.c_str(), _TRUNCATE);
            out.details.file_read.zone_id =
                GetZoneIdentifier(path_utf8);
            out.details.file_read.bytes_requested =
                TdhGetULongProperty(event, info, L"IoSize");
            should_emit = true;
        }
    }

    // ── Microsoft-Windows-Kernel-Network ─────────────────────────────────────
    else if (IsEqualGUID(event->EventHeader.ProviderId, KernelNetworkGuid)) {

        if (event_id == KERNEL_NETWORK_TCP_CONNECT) {
            out.header.event_type = EventType::NetworkConnect;

            // Remote address is a binary SOCKADDR; extract as text
            PROPERTY_DATA_DESCRIPTOR daddr_desc = {};
            daddr_desc.PropertyName =
                reinterpret_cast<ULONGLONG>(L"daddr");
            daddr_desc.ArrayIndex = ULONG_MAX;

            ULONG addr_size = 0;
            TdhGetPropertySize(event, 0, nullptr, 1, &daddr_desc, &addr_size);
            if (addr_size >= 4) {
                std::vector<BYTE> addr_buf(addr_size);
                if (TdhGetProperty(event, 0, nullptr, 1, &daddr_desc,
                                   addr_size, addr_buf.data()) == ERROR_SUCCESS) {
                    // IPv4
                    if (addr_size == 4) {
                        struct in_addr ia;
                        memcpy(&ia, addr_buf.data(), 4);
                        inet_ntop(AF_INET, &ia,
                                  out.details.network_connect.destination_ip,
                                  sizeof(out.details.network_connect.destination_ip));
                    } else if (addr_size == 16) {
                        // IPv6
                        struct in6_addr ia6;
                        memcpy(&ia6, addr_buf.data(), 16);
                        inet_ntop(AF_INET6, &ia6,
                                  out.details.network_connect.destination_ip,
                                  sizeof(out.details.network_connect.destination_ip));
                    }
                }
            }

            out.details.network_connect.destination_port =
                static_cast<uint16_t>(
                    ntohs(static_cast<u_short>(
                        TdhGetULongProperty(event, info, L"dport"))));

            strncpy_s(out.details.network_connect.protocol, "TCP", _TRUNCATE);
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

    EVENT_TRACE_LOGFILE log = {};
    log.LoggerName          = const_cast<LPWSTR>(SESSION_NAME);
    log.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                              PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EtwConsumer::EventRecordCallback;

    TRACEHANDLE th = OpenTrace(&log);
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
        ControlTrace(session_handle_, nullptr, props,
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
