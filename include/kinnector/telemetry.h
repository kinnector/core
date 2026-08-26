#ifndef KINNECTOR_TELEMETRY_H
#define KINNECTOR_TELEMETRY_H

#include <cstdint>

#pragma pack(push, 1)

enum class EventType : uint8_t {
    ProcessCreate = 1,
    ProcessStop = 2,
    FileRead = 3,
    FileCreate = 4,
    FileWrite = 5,
    FileRename = 6,
    NetworkConnect = 7,
    ImageLoad = 8,
    RegistryWrite = 9,
    ClipboardWrite = 10,
    CallStackFrame = 11,
    MemoryProtect = 12,
    PtraceAttach = 13,
    SSHAuth = 14,
    TerminalCommand = 15,
    FileOpen = 16,
    MemoryMap = 17,
    Dup2 = 18,
    Listen = 19,
    NetworkAccept = 20,
    DNSQuery = 21,
    FileDelete = 22,
    SignalDelivery = 23,
    PrivilegeChange = 24,
    IPCAccess = 25,
    TaskRegistered = 26,
    CrossProcessMemoryAccess = 27,
    ThreadContextAccess = 28,
    ImpersonationChange = 29,
    DpapiOperation = 30
};

enum class TelemetrySource : uint8_t {
    ETW = 1,
    ESF = 2,
    OpenBSM = 3,
    eBPF = 4,
    fanotify = 5,
    BPF_LSM = 6,
    Log_FIM = 7,
    Clipboard = 8,
    CallStack = 9
};

struct TelemetryHeader {
    uint64_t sequence_number;
    uint64_t timestamp_ns;
    uint32_t pid;
    EventType event_type;
    TelemetrySource source;
};

// Sub-details structures corresponding to ALERT-SCHEMA.md types
struct ProcessCreateDetails {
    uint32_t child_pid;
    uint32_t real_parent_pid;
    char child_image_path[512];
    char child_command_line[1024];
    // Reuse-resistant per-boot process identifiers (Windows Kernel-Process
    // ProcessSequenceNumber/ParentProcessSequenceNumber). 0 means "not
    // available on this OS build" (older Windows), not "sequence number 0" -
    // callers must not treat 0 as a valid sequence value for lineage keying.
    uint64_t child_sequence_number;
    uint64_t parent_sequence_number;
};

struct ProcessStopDetails {
    int32_t exit_code;
};

struct FileReadDetails {
    uint32_t bytes_requested;
    int32_t zone_id; // -1 if not set, or Windows ZoneId (3=internet, 4=untrusted)
    char file_path[512];
};

struct FileCreateDetails {
    int32_t zone_id;
    char file_path[512];
};

struct FileWriteDetails {
    uint32_t bytes_written;
    char file_path[512];
};

struct FileRenameDetails {
    char source_path[512];
    char destination_path[512];
};

struct FileDeleteDetails {
    char file_path[512];
};

struct NetworkConnectDetails {
    char destination_ip[46]; // support IPv6
    uint16_t destination_port;
    char protocol[8];        // TCP, UDP
};

struct NetworkAcceptDetails {
    char remote_ip[46];   // the connecting peer, support IPv6
    uint16_t remote_port;
    uint16_t local_port;  // the listening port the connection arrived on
};

struct ImageLoadDetails {
    uint8_t is_signed;
    char module_path[512];
    char signer_subject[256];
};

struct RegistryWriteDetails {
    char key_path[512];
    char value_name[256];
    char value_data[512];
};

struct TaskRegisteredDetails {
    char task_name[512];
    char user_context[256];
};

// Cross-process memory operations (VirtualAlloc/VirtualProtect/
// WriteProcessMemory targeting a different process). Detection-only
// telemetry - records what happened, not an assessment of intent.
struct CrossProcessMemoryAccessDetails {
    uint32_t target_pid;
    uint64_t address;
    uint64_t size;
    char operation[32];  // "VirtualAlloc", "VirtualProtect", "WriteProcessMemory"
    char protection[64]; // page protection flags, when applicable
};

// Cross-process thread operations (SetThreadContext/QueueUserAPC/remote
// thread creation targeting a different process). Detection-only telemetry.
struct ThreadContextAccessDetails {
    uint32_t target_pid;
    uint32_t target_tid;
    uint64_t start_address; // function pointer target, 0 if not applicable
    char operation[32];     // "SetThreadContext", "QueueUserAPC", "RemoteThreadCreate"
};

// A thread's effective identity changing (impersonation applied/reverted).
// Records the calling thread and what its token looked like immediately
// before the change - pure data capture, no interpretation of whether the
// change is expected or not (that's a policy-layer decision).
struct ImpersonationChangeDetails {
    uint32_t calling_pid;
    uint32_t calling_tid;
    char direction[8];               // "UP", "DOWN", "REVERT"
    char previous_token_user[256];
    char previous_token_integrity[32];
    uint8_t previous_token_elevated;
};

// Microsoft-Windows-Crypto-DPAPI's DPAPIDefInformationEvent (Id=16385, Task=64
// ETW_TASK_DEF_INFORMATION, gated behind the Debug channel keyword
// 0x2000000000000000 - see etw_consumer.cpp / WINDOWS_COVERAGE_PLAN.md Phase 6).
//
// EMPIRICALLY CONFIRMED LIMITATION: this event fires only for a process'
// FIRST DPAPI operation (Protect or Unprotect) in its lifetime, not per-call -
// a long-lived process making repeated CryptUnprotectData calls only produces
// ONE of these events total. Treat this as a "process used DPAPI at least
// once" signal, not a full per-operation audit trail.
//
// PID ATTRIBUTION - IMPORTANT DEVIATION FROM EVERY OTHER EVENT TYPE IN THIS
// FILE: DPAPI master-key operations are actually carried out by lsass.exe on
// the caller's behalf, so this event's raw ETW EventHeader.ProcessId is
// ALWAYS lsass.exe (confirmed empirically - QueryFullProcessImageNameW
// resolved it to C:\Windows\System32\lsass.exe, not the calling test
// process), never the real caller. Every other event type in telemetry.h
// sets TelemetryHeader.pid from EventHeader.ProcessId directly and that's
// correct there; for DpapiOperation specifically, etw_consumer.cpp
// deliberately overrides header.pid with this struct's own caller_pid
// (parsed from the CallerProcessID property) instead, since leaving it as
// lsass.exe's PID would make the field useless for 100% of these events.
struct DpapiOperationDetails {
    char operation_type[32];     // "SPCryptProtect" or "SPCryptUnprotect"
    // App-supplied, UNTRUSTED for attribution - a malicious/careless caller
    // controls this string directly (it's CryptProtectData's szDataDescr
    // argument), don't treat it as proof of which credential store was
    // touched. Real attribution needs to correlate the calling process
    // identity/master_key_guid against the config domain (§7)/owner-allowlist
    // model (§4), same as every other resource-ownership decision.
    char data_description[256];
    uint8_t master_key_guid[16]; // raw GUID bytes, not yet formatted
    uint32_t flags;
    uint32_t protection_flags;
    int32_t return_value;        // 0 == success
    uint32_t plaintext_data_size;
    // The real calling process' reuse-resistant composite identity - NEVER
    // key attribution on caller_pid alone, same PID-reuse discipline as
    // every lineage table elsewhere in this design (antitheft.md §3/§4,
    // core_windows_phase2_lineage). caller_pid duplicates header.pid (see
    // above) but is kept here too so the raw parsed value is always
    // available even if a future change stops overriding header.pid.
    uint32_t caller_pid;
    uint64_t caller_process_creation_time;
    // Windows' own separate composite process-identity value for this
    // event. Semantics not independently verified against
    // caller_process_creation_time above or against Kernel-Process's
    // ProcessSequenceNumber (core_windows_phase2_lineage) - treat as an
    // opaque correlation key scoped to this provider, not confirmed
    // equivalent to either.
    uint64_t caller_process_start_key;
};

struct ClipboardWriteDetails {
    uint32_t owner_pid;
    uint8_t owner_is_foreground;
    char previous_content[512];
    char new_content[512];
    char content_type[32]; // e.g. BTC_BECH32
    char attribution[16];   // ATTRIBUTED or NULL_OWNER
};

struct CallStackFrameDetails {
    uint32_t frame_index;
    uint64_t return_address;
    uint8_t is_file_backed;
    char module_path[512];
    char notes[128];
};

struct MemoryProtectDetails {
    uint32_t target_pid;
    uint64_t address;
    uint64_t length;
    char prot_flags[64];
    char old_prot_flags[64];
};

struct PtraceAttachDetails {
    uint32_t target_pid;
    char mode[32]; // e.g. PTRACE_ATTACH
};

struct SSHAuthDetails {
    char username[64];
    char source_ip[46];
    uint16_t port;
    char auth_method[32]; // publickey, password
    char status[16];      // SUCCESS, FAILURE
};

struct TerminalCommandDetails {
    char tty_device[32]; // e.g. /dev/pts/1
    char command[512];
};

struct TelemetryEvent {
    TelemetryHeader header;
    union {
        ProcessCreateDetails process_create;
        ProcessStopDetails process_stop;
        FileReadDetails file_read;
        FileCreateDetails file_create;
        FileWriteDetails file_write;
        FileRenameDetails file_rename;
        FileDeleteDetails file_delete;
        NetworkConnectDetails network_connect;
        NetworkAcceptDetails network_accept;
        ImageLoadDetails image_load;
        RegistryWriteDetails registry_write;
        TaskRegisteredDetails task_registered;
        CrossProcessMemoryAccessDetails cross_process_memory_access;
        ThreadContextAccessDetails thread_context_access;
        ImpersonationChangeDetails impersonation_change;
        DpapiOperationDetails dpapi_operation;
        ClipboardWriteDetails clipboard_write;
        CallStackFrameDetails call_stack_frame;
        MemoryProtectDetails memory_protect;
        PtraceAttachDetails ptrace_attach;
        SSHAuthDetails ssh_auth;
        TerminalCommandDetails terminal_command;
    } details;
};

#pragma pack(pop)

#endif // KINNECTOR_TELEMETRY_H
