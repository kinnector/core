# kinnector Core - Kernel-Level Telemetry Engine for EDR (eBPF, BPF LSM, ETW, ESF)

kinnector Core is a native C++ library that captures kernel-level security telemetry on Linux, Windows, and macOS and streams it to a user-space agent over a Unix domain socket. It is the low-level collection layer used by [kinnector Warden](https://github.com/kinnector/warden) and kinnector Antitheft, built for anyone writing an EDR, host-based intrusion detection, runtime security, or endpoint monitoring agent who needs kernel-grade visibility without hand-rolling eBPF loaders from scratch.

If you're evaluating **eBPF-based process monitoring**, **BPF LSM enforcement hooks**, **fanotify file access control on Linux**, **ETW consumption on Windows**, or the **macOS Endpoint Security Framework (ESF)** - this is a working, production-tested reference implementation of all four.

---

## What it does

kinnector Core hooks into OS-native security telemetry sources, captures raw kernel events, serializes them into a compact packed binary format, and delivers them asynchronously over IPC to the consuming agent. On Linux it goes further than passive collection: BPF LSM hooks can return a deny (`-EPERM`/`-EACCES`) synchronously at the hook point, so containment decisions that only need kernel-local state - session classification, trust flags, firewall CIDR matches - execute in-kernel without an IPC round-trip. What Core does *not* do is the higher-level analysis: it doesn't score behavior, correlate events across processes over time, or decide what should be trusted in the first place - that policy authoring happens upstream (in Warden), which populates the maps Core enforces against.

```
[ OS Subsystems ] → [ eBPF/ETW/ESF Hooks ] → [ Ring Buffer ] → [ Serialization ] → [ Unix Socket / IPC ] → [ Your Agent ]
```

This separation - enforcement mechanism vs. policy authoring - is deliberate: Core is the small, auditable thing that actually sits in the kernel hot path and says yes or no; deciding *what* the answer should be (which binaries are trusted, which CIDRs are blocked, what counts as sensitive) stays in the agent, reusable across different agents with different policy logic.

## Platform support

| Platform | Status | Mechanism |
|---|---|---|
| **Linux** | Full - process, file, network, memory, terminal/SSH, container-boundary coverage, enforcement-capable via BPF LSM | eBPF (kprobes, tracepoints, BPF LSM hooks) + `fanotify` |
| **Windows** | Partial - telemetry collection only, no kernel-driver enforcement layer yet | Event Tracing for Windows (ETW), kernel providers: `Kernel-Process`, `Kernel-File`, `Kernel-Network`; clipboard monitoring via `AddClipboardFormatListener` |
| **macOS** | Not yet implemented - design doc only (`src/macos/MACOS_COVERAGE_PLAN.md`), no source | Endpoint Security Framework (ESF) + FSEvents + OpenBSM (planned) |

Linux is the reference implementation and the only backend capable of active enforcement (via BPF LSM return values), not just passive telemetry. Windows currently observes via ETW but its kernel driver integration (`DriverHelper`) is a stub with no enforcement logic - clipboard writes are captured separately (outside ETW, via the Win32 clipboard-listener API) and reported with owner-process attribution, but this is raw collection only, same caveat as the rest of Windows: no in-kernel blocking, and no hijack/tamper detection logic sits on top of it yet. macOS has no code yet - treat it as a roadmap item, not a supported target.

## Linux: hooks by category

`kinnector.bpf.c` compiles against the host kernel's BTF (`vmlinux.h`) and attaches BPF LSM hooks (enforcement-capable - can deny the underlying operation) and tracepoints/kprobes (observation-only) across these categories:

**Session classification & enforcement**
Every process tree is classified in-kernel as it's created - a plain untrusted process, an interactive admin session (detected via `loginuid` plus TTY/PTY attachment heuristics), an install session, or a trusted-admin tree (executing a known admin binary like `logrotate`, `apache2ctl`, `pg_ctl`). That classification (`TREE_ADMIN_SESSION`, `TREE_TRUSTED_ADMIN` flags in a per-PID map) gates dozens of the decisions below - e.g. a trusted-admin tree is restricted to an explicit allowed-command set and denied (`-EACCES`) otherwise, and unprivileged `sshd`-UID processes are denied execution outright as a pre-auth zero-trust lockdown.

**Firewall**
`add_firewall_cidr`/`remove_firewall_cidr` (exposed over FFI) populate an in-kernel CIDR rule table that's checked directly in the network LSM hooks, ahead of role-based sandboxing - an explicit firewall DENY wins immediately. The rule store and diffing (which CIDRs should exist) is owned by the calling agent; Core owns the packet-path enforcement decision itself.

**Process execution & lifecycle**
- `lsm/bprm_creds_for_exec`, `lsm/bprm_check_security` - vet and can block process execution
- `tracepoint/sys_enter_execve`, `sched_process_fork`, `sched_process_exit` - creation, forking, termination with parent-child lineage
- `lsm/task_kill` - signal delivery between processes
- `lsm/task_fix_setuid` - privilege changes

**Filesystem access**
- `lsm/file_open`, `lsm/file_permission` - vet and can deny access to any file on the filesystem, not just a hooked subset - decisions are driven by the sensitive/protected/trusted inode maps (`add_sensitive_inode`, `add_protected_static_inode`, `add_trusted_exec_inode`) populated over FFI
- `lsm/inode_unlink` - file deletion, deniable the same way
- `lsm/path_chmod`, `lsm/path_chroot`, `lsm/sb_mount` - permission changes, chroot jails, mount events; `sb_mount`/`path_chroot` are actively denied for namespace-restricted containers (see Container & namespace boundaries below)
- memfd-backed binary execution and `/proc/<pid>/fd`-based local file inclusion (LFI) are denied at the same hook layer
- `fanotify` - complementary filesystem-wide monitoring outside the BPF LSM path

**Network**
- `lsm/socket_connect`, `lsm/socket_listen`, `lsm/socket_accept`, `lsm/socket_sendmsg` - vet and can block outbound/inbound connections
- `tracepoint/sys_enter_connect`, `sys_enter_listen` - connection observation

**Memory & process introspection**
- `lsm/file_mprotect`, `lsm/mmap_file` - memory protection and mapping changes
- `lsm/ptrace_access_check` - debugger/injection attachment attempts
- `lsm/shm_shmat` - shared memory attachment

**Container & namespace boundaries**
- `tracepoint/sys_enter_setns`, `sys_enter_unshare` - namespace entry/creation, used for container-aware session tracking
- restricted-container processes are actively denied `mount` and `chroot` attempts (container sandboxing / escape prevention), not just observed

**Terminal & SSH**
- `kprobe/tty_write`, `kprobe/tty_read` - decrypted SSH session and terminal command capture, read pre-encryption so it works regardless of SSH cipher

Events are delivered through two `BPF_MAP_TYPE_RINGBUF` ring buffers - a 16MB `telemetry_ringbuf` for general kernel events, and a dedicated 4MB `tty_ringbuf` for terminal I/O - each drained by a user-space polling thread that serializes events into the `TelemetryEvent` wire format and forwards them over Unix domain sockets (a general telemetry socket and a separate one for TTY/SSH data).

Map capacity for all of the above (process/inode/session-tracking maps) is auto-sized at load time from host RAM across fine-grained tiers, rather than fixed at a single constant regardless of machine size.

## Captured event types

25 distinct event types across process lifecycle, filesystem, network, memory, and terminal/SSH activity - process creation/termination with full parent-child lineage, file open/read/write/create/rename/delete, network connect/accept/listen/DNS query, `mprotect`/memory-map changes, `ptrace` attachment, privilege changes, signal delivery, IPC access, clipboard writes, call-stack frames, and decrypted SSH auth/terminal commands. See `include/kinnector/telemetry.h` for the full `EventType` enum and per-event payload structs.

Every event shares a common `TelemetryHeader` (sequence number, nanosecond timestamp, PID, event type, source) followed by a type-specific payload, packed into a fixed 1582-byte `TelemetryEvent` frame - cheap to serialize, cheap to parse, no dynamic allocation on the hot path.

## Using it from any FFI-capable language

kinnector Core builds as both a static (`kinnector-core`) and shared (`libkinnector-core`) library via CMake, and the entire public surface (`include/kinnector/ffi.h`) is a flat C ABI - no C++ name mangling, no STL types crossing the boundary. That means it's directly callable from **any language with a foreign function interface**: C, C++, Rust, Go, Python, Node.js, Java, C#, and more. There are no official language bindings shipped yet - the examples below call the shared library straight through each language's native FFI layer.

**C / C++**
```c
#include "kinnector/ffi.h"

initialize_telemetry_engine("/path/to/kinnector.bpf.o", "/var/run/kinnector/telemetry.sock", "your-auth-token");
start_telemetry_engine();
// ... your agent consumes TelemetryEvent frames from the socket ...
stop_telemetry_engine();
```

**Python** (via `ctypes`, no extra dependencies) - for a BPF LSM / eBPF security agent written in Python:
```python
import ctypes

lib = ctypes.CDLL("./libkinnector-core.so")

lib.initialize_telemetry_engine.restype = ctypes.c_bool
lib.initialize_telemetry_engine.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

lib.initialize_telemetry_engine(
    b"/path/to/kinnector.bpf.o",
    b"/var/run/kinnector/telemetry.sock",
    b"your-auth-token",
)
lib.start_telemetry_engine()

# is_lsm_active() confirms the BPF LSM hooks actually loaded into the kernel
lib.is_lsm_active.restype = ctypes.c_bool
print("LSM active:", lib.is_lsm_active())

lib.stop_telemetry_engine()
```

**Rust** (via `extern "C"` + a build-time `libloading`/`bindgen`-generated binding, or by linking `kinnector-core` directly from a `build.rs`):
```rust
#[link(name = "kinnector-core")]
extern "C" {
    fn initialize_telemetry_engine(bpf_obj_path: *const i8, socket_path: *const i8, auth_token: *const i8) -> bool;
    fn start_telemetry_engine() -> bool;
    fn stop_telemetry_engine();
}
```

**Go** (via `cgo`):
```go
/*
#cgo LDFLAGS: -lkinnector-core
#include "kinnector/ffi.h"
*/
import "C"

func StartTelemetry(bpfObj, socketPath, authToken string) bool {
    return bool(C.initialize_telemetry_engine(C.CString(bpfObj), C.CString(socketPath), C.CString(authToken))) &&
        bool(C.start_telemetry_engine())
}
```

**Node.js** (via `ffi-napi` / `koffi`):
```javascript
const koffi = require("koffi");
const lib = koffi.load("./libkinnector-core.so");

const initEngine = lib.func("bool initialize_telemetry_engine(const char*, const char*, const char*)");
const startEngine = lib.func("bool start_telemetry_engine()");

initEngine("/path/to/kinnector.bpf.o", "/var/run/kinnector/telemetry.sock", "your-auth-token");
startEngine();
```

`initialize_telemetry_engine`/`start_telemetry_engine`/`stop_telemetry_engine` only get the collection engine running - the interesting part for a language like Python is everything downstream of that: reading the events it emits, and using the FFI surface to configure what it should deny.

### Consuming events: your agent is the socket server, Core is the client

Core doesn't expose a "give me the next event" FFI call - it dials out to a Unix socket your agent listens on, and pushes raw, fixed-size `TelemetryEvent` frames (1582 bytes each, `#pragma pack(1)`, no length prefix needed since the size is constant). If `auth_token` was non-empty at `initialize_telemetry_engine`, Core sends a 4-byte little-endian token length + the token bytes first, and blocks until your server writes back a single status byte (`1` = accepted, anything else = rejected). This is enough to build a full consumer in pure Python with no FFI at all:

```python
import socket, struct, os

SOCK_PATH = "/var/run/kinnector/telemetry.sock"
EXPECTED_TOKEN = b"your-auth-token"

# TelemetryHeader layout (see include/kinnector/telemetry.h): packed,
# no padding -> 8+8+4+1+1 = 22 bytes, followed by a 1560-byte event payload.
HEADER_FMT = "<QQIBB"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
EVENT_SIZE = 1582

EVENT_TYPES = {
    1: "ProcessCreate", 2: "ProcessStop", 3: "FileRead", 4: "FileCreate",
    5: "FileWrite", 6: "FileRename", 7: "NetworkConnect", 13: "PtraceAttach",
    14: "SSHAuth", 15: "TerminalCommand", 22: "FileDelete", 24: "PrivilegeChange",
    # ... full enum in include/kinnector/telemetry.h
}

os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
if os.path.exists(SOCK_PATH):
    os.remove(SOCK_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCK_PATH)
server.listen(1)

conn, _ = server.accept()

# Handshake: read 4-byte length, then that many bytes of token
token_len = struct.unpack("<I", conn.recv(4))[0]
token = conn.recv(token_len)
conn.send(b"\x01" if token == EXPECTED_TOKEN else b"\x00")

while True:
    frame = conn.recv(EVENT_SIZE)
    if len(frame) < EVENT_SIZE:
        break
    seq, ts_ns, pid, event_type, source = struct.unpack(HEADER_FMT, frame[:HEADER_SIZE])
    payload = frame[HEADER_SIZE:]
    print(f"[{seq}] pid={pid} type={EVENT_TYPES.get(event_type, event_type)} ts={ts_ns}")
    # decode `payload` per event_type using the matching *Details struct layout
```

### Setting up blockers (deny rules)

The FFI surface lets you build your own policy layer on top of the raw telemetry - populate these maps and the *same* LSM hooks that generate events will start denying the operations they cover:

```c
#include "kinnector/ffi.h"

// Deny any process from opening this file (dev/inode identify it uniquely
// across bind-mounts) - category is your own classification tag.
add_sensitive_inode(root_dev, secrets_file_inode, /*category=*/1);

// Hard-deny: nobody may ever access this inode, no exceptions.
add_protected_static_inode(root_dev, config_file_inode);

// Mark a binary's inode as trusted to execute at a given trust level.
add_trusted_exec_inode(trusted_binary_inode, /*trust_level=*/2);

// Deny outbound connections to 203.0.113.0/24 on port 4444 (eBPF-enforced,
// checked ahead of role-based sandboxing in the network LSM hooks).
uint8_t cidr[4] = {203, 0, 113, 0};
add_firewall_cidr(/*is_v6=*/false, cidr, /*prefixlen=*/24, /*rule_id=*/1,
                   /*port=*/4444, /*proto=*/IPPROTO_TCP, /*direction=*/0, /*action=*/1);
```

### Distinguishing and setting session types

Every process tree carries a bitflag classification (`TREE_ADMIN_SESSION`, `TREE_TRUSTED_ADMIN`, defined in `kinnector.bpf.c`) that gates enforcement decisions in-kernel - e.g. a `TREE_TRUSTED_ADMIN` tree gets a restricted command allowlist instead of full denial, and an `TREE_ADMIN_SESSION` interactive login gets different filesystem-access defaults than a plain untrusted process. The kernel consults these flags directly, so they aren't read back over FFI, but your agent can *set* them via the generic map-entry calls (`update_map_entry`/`delete_map_entry`) using the target map's index in the `BpfMapType` enum (`src/linux/ebpf_loader.h`):

```c
#include "kinnector/ffi.h"

// BpfMapType::PidTreeType == 9 in the current enum order - reclassify a PID's
// tree as an admin session so it's exempted from restrictions that would
// otherwise apply to a plain untrusted process.
#define BPF_MAP_TYPE_PID_TREE_TYPE 9
update_map_entry(BPF_MAP_TYPE_PID_TREE_TYPE, pid, start_time, /*TREE_ADMIN_SESSION=*/0x00010000u);

// BpfMapType::TrustedAdminBinaries == 15 - register a binary's inode as a
// trusted admin tool; any process tree spawned from it becomes TREE_TRUSTED_ADMIN.
#define BPF_MAP_TYPE_TRUSTED_ADMIN_BINARIES 15
update_map_entry(BPF_MAP_TYPE_TRUSTED_ADMIN_BINARIES, /*pid unused*/0, admin_binary_inode, 1);

// Revert a PID's classification once its privileged window is over.
delete_map_entry(BPF_MAP_TYPE_PID_TREE_TYPE, pid, start_time);
```

Note: `BpfMapType` is currently an internal enum (`ebpf_loader.h`, not `ffi.h`), so these indices are a real dependency on file layout, not a stable public API - they'll break silently if the enum is reordered. If you're calling this from outside the C++ codebase, pin against a specific commit/tag of this repo, or ask upstream to promote `BpfMapType` into the public `ffi.h` header.

## Performance

Core is designed to sit on syscall-hot paths system-wide (`file_open`/`file_permission`/`ptrace_access_check` fire on every relevant syscall, on every process, on the host it's loaded on), so the design constraint throughout is: do the minimum possible work in-kernel, and never let userspace latency or allocation stalls sit on the enforcement path.

**Fixed-size, zero-allocation event frames.** Every `TelemetryEvent` is a `#pragma pack(1)` struct, always exactly 1582 bytes, written directly into ring buffer memory and read directly off the socket - no dynamic allocation, no variable-length encoding/decoding, on either side of the IPC boundary.

**Per-CPU state to avoid cross-core contention.** The event sequence counter (`seq_counter`) and a scratch buffer used to stage large structs before a map write (`scratch_map`) are both `BPF_MAP_TYPE_PERCPU_ARRAY` - each CPU gets its own copy, so no atomic increment or lock is shared across cores on the hot path. The scratch buffer also sidesteps eBPF's ~512-byte verifier stack limit for structs too large to build on the BPF stack directly.

**In-kernel event coalescing.** High-frequency, low-value-per-event operations (repeated file reads/writes/exec/mmap/syscalls from the same PID against the same inode) are coalesced in `fs_batch_map` instead of emitting one ring buffer event per syscall: occurrences are counted and only flushed as a single aggregated event once per second or every 500 occurrences, whichever comes first. This is what keeps a `tar`-extracting install script or a build system doing thousands of file operations a second from flooding the ring buffer or the IPC socket.

**16MB/4MB ring buffers, sized to absorb bursts without dropping events**, drained by a dedicated user-space polling thread (`ring_buffer__poll`, libbpf's epoll-backed API - it wakes immediately when data arrives; the poll call's timeout argument is only the ceiling for how long it blocks when idle, not a fixed sampling interval).

**RAM-tiered map auto-sizing.** Process/inode/session-tracking hash map capacities scale with host memory at load time instead of using one fixed constant for every machine - a small container host doesn't pay for capacity it'll never need, and a busy multi-tenant host doesn't silently start evicting entries under load.

**A lock-light IPC path.** The Linux telemetry sender's connection state (`running_`, `connected_`, `socket_fd_`) is `std::atomic`, so the send path only takes a mutex around the actual `write()` call - not around connection-state checks - keeping the userspace side of the hot path short.

What this section deliberately doesn't claim: there are no published throughput/latency benchmark numbers in this repo yet (the coverage-plan docs call for a stress-test pass under real workloads like `stress-ng --fork`, but it hasn't been run and captured here) - the above describes the actual mechanisms in the code, not measured results.

## Build

**Prerequisites**
* CMake 3.20+
* Clang/LLVM (for eBPF compilation on Linux)
* Linux kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)

```bash
cmake -B build
cmake --build build --config Release
```

**Test binaries** (Linux): `kinnector-test-ipc`, `kinnector-test-lsm`, `kinnector-test-telemetry`, `kinnector-test-warden-helper`, `kinnector-test-fanotify`, `kinnector-test-ebpf-loader`, `kinnector-test-linux-ipc`, `kinnector-test-ffi`, `kinnector-test-warden-all`, `kinnector-enforcement-probe`, `kinnector-test-enforcement-e2e`.

```bash
# Verify IPC serialization end-to-end
./build/bin/kinnector-test-ipc

# Verify eBPF/BPF LSM hook compilation and attachment (requires root)
sudo ./build/bin/kinnector-test-lsm

# Full enforcement path, live, as root
sudo ./build/bin/kinnector-test-enforcement-e2e
```

## Who this is for

If you're building an EDR agent, a runtime application self-protection (RASP) layer, a container-aware intrusion detection system, or any tool that needs kernel-level process/file/network visibility on Linux, Windows, or macOS - kinnector Core gives you the collection layer so you can focus on detection logic instead of eBPF loader plumbing, LSM hook wiring, or ETW session management.
