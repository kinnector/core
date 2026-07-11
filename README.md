# Kinnector Core

Kinnector Core is the native, low-level event collection and telemetry engine for the Kinnector security agent. It captures kernel-level and system-level events across Linux, Windows, and macOS, serving as the foundational event provider for behavioral heuristics engines.

---

## Why this exists

Endpoint Detection and Response (EDR) systems require real-time visibility into process lifecycle events, file system access, network socket calls, and memory permissions. Performing this inspection directly within latency-sensitive execution paths can introduce CPU overhead and destabilize the operating system. 

Kinnector Core solves this by leveraging native kernel-level telemetry and event mechanisms, offloading analysis to user-space daemons asynchronously via high-performance ring buffers.

---

## Mental Model

```
[ OS Subsystems ] ──(Raw Events)──> [ Telemetry Hooks ] ──(Serialization)──> [ Unix Socket / IPC ]
```

Kinnector Core hooks operating system subsystems, captures raw security-relevant parameters, serializes them into packed binary structures, and delivers them via IPC to the local agent. The engine does not evaluate policy rules or decide containment actions; its sole responsibility is accurate, low-overhead event collection.

---

## Subsystem Integrations

The engine interfaces with native kernel and user-space telemetry frameworks:

* **Linux**: Uses eBPF (Extended Berkeley Packet Filter) hooks (`kprobes`, `tracepoints`, and BPF LSM), combined with `fanotify` for file system monitoring.
* **Windows**: Interfaces with Event Tracing for Windows (ETW) for system event subscription.
* **macOS**: Utilizes the native Endpoint Security Framework (ESF) and FSEvents.

---

## Capabilities and Captured Events

Kinnector Core monitors and serializes the following event categories:

* **Process Management**: Process creation (`execve`), process termination, parent-child inheritance tracking, and command-line arguments.
* **Network Sockets**: TCP/UDP connections (IPv4 and IPv6) and destination addresses.
* **File System Operations**: File open, read, write, create, rename, and deletion events.
* **Memory & Security Subsystems**: Memory protection modifications (`mprotect` executions) and process debugging attachments (`ptrace` checks).

---

## Architecture & Data Flow (Linux Engine)

### 1. eBPF LSM Event Capture
On Linux, Kinnector Core compiles `kinnector.bpf.c` against the host kernel's BTF (`vmlinux.h`). The loaders attach probes and Linux Security Module (LSM) hooks:
* `lsm/bprm_creds_for_exec` - Traces process executions.
* `lsm/file_open` - Intercepts file access attempts.
* `lsm/socket_connect` - Validates outbound network connections.
* `lsm/ptrace_access_check` - Captures memory debugger attachments.
* `lsm/file_mprotect` - Monitors execution page allocation shifts.

Intercepted parameters are written to the kernel's `telemetry_ringbuf` ring buffer.

### 2. User-Space Serialization and Delivery
A background polling thread in user space consumes raw events from the ring buffer. The payload is cast into a packed binary structure (`TelemetryEvent`, 1566 bytes frame size) and sent via a Unix domain socket at `/var/run/kinnector/telemetry.sock` to the agent.

---

## Build and Verification

### Prerequisites
* CMake 3.20+
* Clang/LLVM (for eBPF compilation on Linux)
* Linux kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)

### Compiling
Compile the project and native test binaries using CMake:

```bash
cmake -B build
cmake --build build --config Release
```

### Telemetry Verification
Run the built-in IPC loop test to verify message serialization and socket communication:

```bash
./build/bin/kinnector-test-ipc
```

Verify eBPF LSM hook compilation and attachment (requires root privileges):

```bash
sudo ./build/bin/kinnector-test-lsm
```