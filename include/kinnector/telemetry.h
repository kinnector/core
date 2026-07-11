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
    TerminalCommand = 15
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

struct NetworkConnectDetails {
    char destination_ip[46]; // support IPv6
    uint16_t destination_port;
    char protocol[8];        // TCP, UDP
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
        NetworkConnectDetails network_connect;
        ImageLoadDetails image_load;
        RegistryWriteDetails registry_write;
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
