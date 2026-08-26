#include "kinnector/telemetry.h"
#include <iostream>
#include <cstring>
#include <cassert>
#include <vector>

// Verify packed struct sizes right at compile time
static_assert(sizeof(TelemetryHeader) == 22, "TelemetryHeader size must be 22 bytes");
static_assert(sizeof(TelemetryEvent) == 1582, "TelemetryEvent size must be packed to 1582 bytes");

void TestHeaderAndEnums() {
    std::cout << "[TestTelemetry] Testing TelemetryHeader alignment and Enum values..." << std::endl;
    
    assert(static_cast<uint8_t>(EventType::ProcessCreate) == 1);
    assert(static_cast<uint8_t>(EventType::ProcessStop) == 2);
    assert(static_cast<uint8_t>(EventType::FileRead) == 3);
    assert(static_cast<uint8_t>(EventType::FileCreate) == 4);
    assert(static_cast<uint8_t>(EventType::FileWrite) == 5);
    assert(static_cast<uint8_t>(EventType::FileRename) == 6);
    assert(static_cast<uint8_t>(EventType::NetworkConnect) == 7);
    assert(static_cast<uint8_t>(EventType::ImageLoad) == 8);
    assert(static_cast<uint8_t>(EventType::RegistryWrite) == 9);
    assert(static_cast<uint8_t>(EventType::ClipboardWrite) == 10);
    assert(static_cast<uint8_t>(EventType::CallStackFrame) == 11);
    assert(static_cast<uint8_t>(EventType::MemoryProtect) == 12);
    assert(static_cast<uint8_t>(EventType::PtraceAttach) == 13);
    assert(static_cast<uint8_t>(EventType::SSHAuth) == 14);
    assert(static_cast<uint8_t>(EventType::TerminalCommand) == 15);

    assert(static_cast<uint8_t>(TelemetrySource::ETW) == 1);
    assert(static_cast<uint8_t>(TelemetrySource::ESF) == 2);
    assert(static_cast<uint8_t>(TelemetrySource::OpenBSM) == 3);
    assert(static_cast<uint8_t>(TelemetrySource::eBPF) == 4);
    assert(static_cast<uint8_t>(TelemetrySource::fanotify) == 5);
    assert(static_cast<uint8_t>(TelemetrySource::BPF_LSM) == 6);
    assert(static_cast<uint8_t>(TelemetrySource::Log_FIM) == 7);
    assert(static_cast<uint8_t>(TelemetrySource::Clipboard) == 8);
    assert(static_cast<uint8_t>(TelemetrySource::CallStack) == 9);

    TelemetryHeader header{};
    header.sequence_number = 1000;
    header.timestamp_ns = 1234567890ULL;
    header.pid = 4242;
    header.event_type = EventType::ProcessCreate;
    header.source = TelemetrySource::BPF_LSM;

    assert(header.sequence_number == 1000);
    assert(header.timestamp_ns == 1234567890ULL);
    assert(header.pid == 4242);
    assert(header.event_type == EventType::ProcessCreate);
    assert(header.source == TelemetrySource::BPF_LSM);
    
    std::cout << "  - Header and Enums verified successfully." << std::endl;
}

void TestUnionDetailsStructures() {
    std::cout << "[TestTelemetry] Testing all Union Details structures..." << std::endl;

    TelemetryEvent event{};
    std::memset(&event, 0, sizeof(event));

    // 1. ProcessCreateDetails
    event.header.event_type = EventType::ProcessCreate;
    event.details.process_create.child_pid = 101;
    event.details.process_create.real_parent_pid = 100;
    std::strncpy(event.details.process_create.child_image_path, "/usr/bin/wardend", sizeof(event.details.process_create.child_image_path) - 1);
    std::strncpy(event.details.process_create.child_command_line, "/usr/bin/wardend --config /etc/warden.conf", sizeof(event.details.process_create.child_command_line) - 1);
    assert(event.details.process_create.child_pid == 101);
    assert(event.details.process_create.real_parent_pid == 100);
    assert(std::strcmp(event.details.process_create.child_image_path, "/usr/bin/wardend") == 0);
    assert(std::strcmp(event.details.process_create.child_command_line, "/usr/bin/wardend --config /etc/warden.conf") == 0);

    // 2. ProcessStopDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::ProcessStop;
    event.details.process_stop.exit_code = -1;
    assert(event.details.process_stop.exit_code == -1);

    // 3. FileReadDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::FileRead;
    event.details.file_read.bytes_requested = 4096;
    event.details.file_read.zone_id = 3;
    std::strncpy(event.details.file_read.file_path, "/etc/passwd", sizeof(event.details.file_read.file_path) - 1);
    assert(event.details.file_read.bytes_requested == 4096);
    assert(event.details.file_read.zone_id == 3);
    assert(std::strcmp(event.details.file_read.file_path, "/etc/passwd") == 0);

    // 4. FileCreateDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::FileCreate;
    event.details.file_create.zone_id = -1;
    std::strncpy(event.details.file_create.file_path, "/tmp/warden_test.lock", sizeof(event.details.file_create.file_path) - 1);
    assert(event.details.file_create.zone_id == -1);
    assert(std::strcmp(event.details.file_create.file_path, "/tmp/warden_test.lock") == 0);

    // 5. FileWriteDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::FileWrite;
    event.details.file_write.bytes_written = 1024;
    std::strncpy(event.details.file_write.file_path, "/var/log/warden.log", sizeof(event.details.file_write.file_path) - 1);
    assert(event.details.file_write.bytes_written == 1024);
    assert(std::strcmp(event.details.file_write.file_path, "/var/log/warden.log") == 0);

    // 6. FileRenameDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::FileRename;
    std::strncpy(event.details.file_rename.source_path, "/tmp/old.txt", sizeof(event.details.file_rename.source_path) - 1);
    std::strncpy(event.details.file_rename.destination_path, "/tmp/new.txt", sizeof(event.details.file_rename.destination_path) - 1);
    assert(std::strcmp(event.details.file_rename.source_path, "/tmp/old.txt") == 0);
    assert(std::strcmp(event.details.file_rename.destination_path, "/tmp/new.txt") == 0);

    // 7. NetworkConnectDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::NetworkConnect;
    std::strncpy(event.details.network_connect.destination_ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", sizeof(event.details.network_connect.destination_ip) - 1);
    event.details.network_connect.destination_port = 443;
    std::strncpy(event.details.network_connect.protocol, "TCP", sizeof(event.details.network_connect.protocol) - 1);
    assert(std::strcmp(event.details.network_connect.destination_ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334") == 0);
    assert(event.details.network_connect.destination_port == 443);
    assert(std::strcmp(event.details.network_connect.protocol, "TCP") == 0);

    // 8. ImageLoadDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::ImageLoad;
    event.details.image_load.is_signed = 1;
    std::strncpy(event.details.image_load.module_path, "/lib/x86_64-linux-gnu/libc.so.6", sizeof(event.details.image_load.module_path) - 1);
    std::strncpy(event.details.image_load.signer_subject, "CN=Canonical Ltd", sizeof(event.details.image_load.signer_subject) - 1);
    assert(event.details.image_load.is_signed == 1);
    assert(std::strcmp(event.details.image_load.module_path, "/lib/x86_64-linux-gnu/libc.so.6") == 0);
    assert(std::strcmp(event.details.image_load.signer_subject, "CN=Canonical Ltd") == 0);

    // 9. RegistryWriteDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::RegistryWrite;
    std::strncpy(event.details.registry_write.key_path, "HKLM\\Software\\Warden", sizeof(event.details.registry_write.key_path) - 1);
    std::strncpy(event.details.registry_write.value_name, "Version", sizeof(event.details.registry_write.value_name) - 1);
    std::strncpy(event.details.registry_write.value_data, "1.0.0", sizeof(event.details.registry_write.value_data) - 1);
    assert(std::strcmp(event.details.registry_write.key_path, "HKLM\\Software\\Warden") == 0);

    // 10. ClipboardWriteDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::ClipboardWrite;
    event.details.clipboard_write.owner_pid = 500;
    event.details.clipboard_write.owner_is_foreground = 1;
    std::strncpy(event.details.clipboard_write.previous_content, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", sizeof(event.details.clipboard_write.previous_content) - 1);
    std::strncpy(event.details.clipboard_write.new_content, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", sizeof(event.details.clipboard_write.new_content) - 1);
    std::strncpy(event.details.clipboard_write.content_type, "BTC_ADDRESS", sizeof(event.details.clipboard_write.content_type) - 1);
    std::strncpy(event.details.clipboard_write.attribution, "ATTRIBUTED", sizeof(event.details.clipboard_write.attribution) - 1);
    assert(event.details.clipboard_write.owner_pid == 500);
    assert(std::strcmp(event.details.clipboard_write.attribution, "ATTRIBUTED") == 0);

    // 11. CallStackFrameDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::CallStackFrame;
    event.details.call_stack_frame.frame_index = 0;
    event.details.call_stack_frame.return_address = 0x7fff12345678ULL;
    event.details.call_stack_frame.is_file_backed = 1;
    std::strncpy(event.details.call_stack_frame.module_path, "/lib/x86_64-linux-gnu/ld.so", sizeof(event.details.call_stack_frame.module_path) - 1);
    std::strncpy(event.details.call_stack_frame.notes, "Valid entry frame", sizeof(event.details.call_stack_frame.notes) - 1);
    assert(event.details.call_stack_frame.return_address == 0x7fff12345678ULL);

    // 12. MemoryProtectDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::MemoryProtect;
    event.details.memory_protect.target_pid = 2000;
    event.details.memory_protect.address = 0x7f8000000000ULL;
    event.details.memory_protect.length = 65536;
    std::strncpy(event.details.memory_protect.prot_flags, "PROT_READ|PROT_WRITE|PROT_EXEC", sizeof(event.details.memory_protect.prot_flags) - 1);
    std::strncpy(event.details.memory_protect.old_prot_flags, "PROT_READ|PROT_WRITE", sizeof(event.details.memory_protect.old_prot_flags) - 1);
    assert(event.details.memory_protect.length == 65536);
    assert(std::strcmp(event.details.memory_protect.prot_flags, "PROT_READ|PROT_WRITE|PROT_EXEC") == 0);

    // 13. PtraceAttachDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::PtraceAttach;
    event.details.ptrace_attach.target_pid = 1;
    std::strncpy(event.details.ptrace_attach.mode, "PTRACE_ATTACH", sizeof(event.details.ptrace_attach.mode) - 1);
    assert(event.details.ptrace_attach.target_pid == 1);
    assert(std::strcmp(event.details.ptrace_attach.mode, "PTRACE_ATTACH") == 0);

    // 14. SSHAuthDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::SSHAuth;
    std::strncpy(event.details.ssh_auth.username, "warden_admin", sizeof(event.details.ssh_auth.username) - 1);
    std::strncpy(event.details.ssh_auth.source_ip, "192.168.1.100", sizeof(event.details.ssh_auth.source_ip) - 1);
    event.details.ssh_auth.port = 2222;
    std::strncpy(event.details.ssh_auth.auth_method, "publickey", sizeof(event.details.ssh_auth.auth_method) - 1);
    std::strncpy(event.details.ssh_auth.status, "SUCCESS", sizeof(event.details.ssh_auth.status) - 1);
    assert(std::strcmp(event.details.ssh_auth.username, "warden_admin") == 0);
    assert(event.details.ssh_auth.port == 2222);

    // 15. TerminalCommandDetails
    std::memset(&event.details, 0, sizeof(event.details));
    event.header.event_type = EventType::TerminalCommand;
    std::strncpy(event.details.terminal_command.tty_device, "/dev/pts/0", sizeof(event.details.terminal_command.tty_device) - 1);
    std::strncpy(event.details.terminal_command.command, "sudo systemctl restart wardend", sizeof(event.details.terminal_command.command) - 1);
    assert(std::strcmp(event.details.terminal_command.tty_device, "/dev/pts/0") == 0);
    assert(std::strcmp(event.details.terminal_command.command, "sudo systemctl restart wardend") == 0);

    std::cout << "  - All 15 union detail structures validated successfully." << std::endl;
}

int main() {
    std::cout << "========================================================\n";
    std::cout << "=== Running Telemetry Structures & Enums Test Suite ===\n";
    std::cout << "========================================================\n";
    TestHeaderAndEnums();
    TestUnionDetailsStructures();
    std::cout << "\n>>> ALL TELEMETRY TESTS PASSED successfully! <<<\n";
    return 0;
}
