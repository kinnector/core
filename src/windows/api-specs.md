# Windows agent ↔ core API spec

How the Rust agent (`antitheftd`) talks to `kinnector-core` on **Windows**, for
the driver-less reactive MVP (`MVP_REACTIVE_PLAN.md`). Linux/macOS are out of
scope here.

There are two channels:

| Direction | Channel | Purpose |
|---|---|---|
| **agent → core** | C FFI (`kinnector-core.dll`, `include/kinnector/ffi.h`) | lifecycle, register protected resources, ask for a verdict, execute a response |
| **core → agent** | a named pipe (agent is the server) | telemetry event stream |

**Boundary (do not blur it):** core *observes* (ETW), *matches* (its in-memory
stores), and *executes* (suspend/terminate/oplock-hold). The agent owns
**config parsing** and **the decision to respond**. Core never reads
`protect-community/configs/antitheft/`.

**No runtime version negotiation.** The agent and core MUST be built from the
same `include/kinnector/telemetry.h` and `include/kinnector/ffi.h`. See
[ABI safety](#abi-safety).

---

## 1. Loading and lifecycle

Link/load `kinnector-core.dll` (the `kinnector-core-shared` build — the static
lib does not export the C API).

### Call order

```
initialize_telemetry_engine(NULL, pipe_name, auth_token)   // NULL = bpf_obj_path, unused on Windows
set_telemetry_profile_windows(1)                           // 1 = reactive; MUST be before start
   ── register everything (see §4) ──
   add_protected_resource_windows(...)          x N
   add_resource_owner_signer_windows(...)       x M
   add_telemetry_path_filter_windows(path)      x N        // one per protected file path
   add_file_guard_windows(path)                 x K        // flagship subset
   set_response_enforcement_windows(1)                     // arm; omit to run detect-only
start_telemetry_engine()
   ── run ──
stop_telemetry_engine()
```

| Function | When callable |
|---|---|
| `initialize_telemetry_engine` | once, first |
| `set_telemetry_profile_windows` | **after `initialize`, before `start`** |
| `add_protected_resource_windows` / `add_resource_owner_signer_windows` / `add_protected_registry_key_windows` / … | after `initialize` (needs `g_running`? — resource setters need `start`; check return) |
| `add_telemetry_path_filter_windows` / `clear_telemetry_path_filter_windows` | any time (before or after `start`) |
| `add_file_guard_windows` / `remove_file_guard_windows` | after `start` |
| `set_response_enforcement_windows` | any time after `initialize` |
| `resolve_actor_windows` / `evaluate_access_windows` / `*_process_windows` / `get_telemetry_stats_windows` | after `start` |
| `stop_telemetry_engine` | last; safe to call if never started |

> Most resource-registration setters return `false` unless the engine is
> *running*. Register **after** `start_telemetry_engine()` succeeds, or in a
> retry loop. `add_telemetry_path_filter_windows` is the exception — it works
> before start.

### Return-value semantics

Every function returns `bool` (except `stop_telemetry_engine` → `void`).
`false` means one of: engine not initialised/running, bad argument, wrong OS,
or the operation failed. Core generally cannot tell the agent *which*. Log and
retry where it makes sense (e.g. registration during startup races).

### Threading

All FFI calls are serialised behind one internal mutex — safe to call from any
thread, including concurrently. Do **not** call FFI from inside your pipe-read
loop if latency matters for other callers; use a worker.

---

## 2. The telemetry pipe (core → agent)

**Core is the pipe client. The agent must be the pipe server.** Core connects
with `CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE, …)` and retries
every **1 s** until it succeeds, and again after any write error — so the agent
should keep the server up and accept reconnections for the process lifetime.

`pipe_name` is the 2nd argument to `initialize_telemetry_engine`
(`socket_path`). Use a standard `\\.\pipe\...` name, e.g.
`\\.\pipe\kinnector-antitheft`.

### Server setup (agent side)

```
CreateNamedPipeA(
    pipe_name,
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    1,                      // one core instance
    64 * 1024, 64 * 1024,   // out/in buffer
    0, &sa)                 // sa: restrict the DACL to SYSTEM/Administrators
ConnectNamedPipe(h, NULL)
```

Duplex is required (core reads a status byte back). Byte mode + fixed-size
framing is the recommended shape.

### Handshake (immediately after connect)

1. Core writes `u32 token_len` (little-endian), then `token_len` bytes of the
   `auth_token` passed to `initialize_telemetry_engine`. (Two separate
   `WriteFile`s — byte mode makes this a stream; read 4 bytes, then `len`.)
2. Agent compares the token. Bound `token_len` (reject absurd values).
3. Agent writes exactly **one byte**: `1` = accept, anything else = reject.
   On reject core closes and retries in 1 s.

### Event stream (after handshake)

Core writes one `TelemetryEvent` per `WriteFile`, **always exactly
`sizeof(TelemetryEvent)` bytes** (see §3). Read fixed-size records:
`read_exact(&mut buf[0..EVENT_SIZE])` → one event. No length prefix, no
delimiter. Native little-endian. If a write fails, core drops the connection
and re-runs the handshake.

There is **no backpressure signalling** — if the agent reads slowly the OS
pipe buffer fills and core's `WriteFile` blocks briefly on the drain thread.
Keep the reader draining into your own queue.

---

## 3. Event ABI (`telemetry.h`)

`#pragma pack(push, 1)` — **no padding anywhere**. Rust: `#[repr(C, packed)]`.

### `TelemetryEvent` = `TelemetryHeader` + a union of detail structs

```
struct TelemetryEvent {
    TelemetryHeader header;   // 30 bytes
    union { ... } details;    // 1560 bytes (size of the largest member, ProcessCreateDetails)
}                             // total: 1590 bytes
```

`EVENT_SIZE == 1590`. Assert it (`const_assert!(size_of::<TelemetryEvent>() == 1590)`).

### `TelemetryHeader` (30 bytes)

| off | size | field | notes |
|---:|---:|---|---|
| 0  | 8 | `sequence_number: u64` | monotonic per core run, event ordering |
| 8  | 8 | `timestamp_ns: u64` | 100 ns ticks since 1601 × 100 → ns since 1601 (system-time clock). Convert: `FILETIME` value = `timestamp_ns / 100`. |
| 16 | 4 | `pid: u32` | the process the event is attributed to |
| 20 | 1 | `event_type: u8` | see enum below |
| 21 | 1 | `source: u8` | always `1` (ETW) on Windows, except clipboard = `8` |
| 22 | 8 | `actor_sequence_number: u64` | **the ABI break.** Kernel-Process `ProcessSequenceNumber` of `pid`, reuse-safe. `0` = unavailable (process pre-dated the engine / old OS) — **never treat 0 as a real value**. |

### `EventType` values the **reactive profile** emits

| val | name | detail struct | payload |
|---:|---|---|---|
| 1  | `ProcessCreate` | `process_create` | `child_pid u32`, `real_parent_pid u32`, `child_image_path[512]`, `child_command_line[1024]`, `child_sequence_number u64`, `parent_sequence_number u64` |
| 2  | `ProcessStop` | `process_stop` | `exit_code i32` |
| 4  | `FileCreate` | `file_create` | `zone_id i32` (−1 in reactive), `file_path[512]` — an ETW `\Device\HarddiskVolumeN\...` path |
| 6  | `FileRename` | `file_rename` | `source_path[512]`, `destination_path[512]` |
| 22 | `FileDelete` | `file_delete` | `file_path[512]` |
| 7  | `NetworkConnect` | `network_connect` | `destination_ip[46]`, `destination_port u16`, `protocol[8]` ("TCP") |
| 20 | `NetworkAccept` | `network_accept` | `remote_ip[46]`, `remote_port u16`, `local_port u16` |
| 26 | `TaskRegistered` | `task_registered` | `task_name[512]`, `user_context[256]` — scheduled-task persistence, **carries the actor via `header.pid`** |
| 30 | `DpapiOperation` | `dpapi_operation` | see the struct in `telemetry.h` — **fires once per process lifetime, not per call**; `header.pid` is overridden to the real caller (raw ETW pid would be lsass) |

`char[N]` fields are NUL-terminated UTF-8, zero-padded to `N`.

### Not emitted in the reactive profile

`FileRead(3)`, `FileWrite(5)`, `ImageLoad(8)`, `RegistryWrite(9)`,
`CrossProcessMemoryAccess(27)`, `ThreadContextAccess(28)`,
`ImpersonationChange(29)` — those need the Full profile / ETW-TI. The agent
should still handle "unknown event_type" gracefully (skip the fixed-size
record).

### Emit-path filter interaction

Once `add_telemetry_path_filter_windows` has been called at least once,
**`FileCreate`/`FileDelete`/`FileRename` are forwarded only when the file
basename (case-insensitive) matches a registered path.** Process / network /
task / DPAPI events are never filtered. So: register a path filter for every
protected file, or you will not see its access events.

---

## 4. FFI reference (agent → core)

### 4.1 Lifecycle

```c
bool initialize_telemetry_engine(const char* bpf_obj_path,   // pass NULL on Windows
                                 const char* socket_path,    // the pipe name
                                 const char* auth_token);
bool start_telemetry_engine(void);
void stop_telemetry_engine(void);
bool set_telemetry_profile_windows(uint32_t profile);        // 0 = full, 1 = reactive
```

### 4.2 Register protected resources

Resources are keyed on the **canonical `(volume_serial, file_reference_number)`**
pair, not a path. Resolve it from the config path:

```rust
// open FILE_READ_ATTRIBUTES, FILE_SHARE_READ|WRITE|DELETE,
// OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS
let info = GetFileInformationByHandle(h)?;
let volume_serial: u32 = info.dwVolumeSerialNumber;
let frn: u64 = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
```

```c
bool add_protected_resource_windows(uint32_t volume_serial, uint64_t frn, uint32_t category);
bool remove_protected_resource_windows(uint32_t volume_serial, uint64_t frn);
bool is_protected_resource_windows(uint32_t volume_serial, uint64_t frn, uint32_t* out_category);

// owner allowlist: Authenticode leaf-signer *display-name subject* (e.g.
// "Microsoft Windows", "AgileBits, Inc."). Any binary signed by an allowlisted
// vendor is authorised - not a pinned hash. Decision is allowlist-only:
// not in the set => denied.
bool add_resource_owner_signer_windows(uint32_t vol, uint64_t frn, const char* signer_subject);
bool remove_resource_owner_signer_windows(uint32_t vol, uint64_t frn, const char* signer_subject);
bool is_authorized_signer_windows(uint32_t vol, uint64_t frn, const char* signer_subject);

// convenience: resolve a binary's live signer and check it in one call
bool is_authorized_modifying_path_windows(uint32_t vol, uint64_t frn, const char* binary_path_utf8);

// telemetry emit filter (see §3). Register one per protected file path.
bool add_telemetry_path_filter_windows(const char* path_utf8);
bool clear_telemetry_path_filter_windows(void);
```

`category` is an opaque `u32` the agent defines (e.g. ssh-key / wallet /
vault / persistence). Core stores and echoes it, does not interpret it.

### 4.3 Flagship file guard (WS7 — synchronous oplock hold)

```c
bool add_file_guard_windows(const char* path_utf8);
bool remove_file_guard_windows(const char* path_utf8);
```

Registers a synchronous hold on `path`. A **foreign** open is held by the OS
while core correlates it to a pid, runs the same owner-set check, and — **only
if UNAUTHORIZED and enforcement is armed** — suspends the opener *before its
first read returns*, then releases. Every other outcome fails open immediately.

- The path must already be registered via `add_protected_resource_windows` +
  `add_resource_owner_signer_windows`, or the guard is armed but inert.
- Entirely handled inside core — the agent just registers it and arms
  enforcement. You will still see the `FileCreate` event afterward.
- Keep the guarded set small (< ~50). Pure usermode, no driver.
- Can't be armed while a legitimate owner already holds the file open — core
  retries.

### 4.4 Resolve an actor

```c
bool resolve_actor_windows(uint32_t pid,
                           uint64_t* out_sequence_number,   // reuse-safe id; 0 = unknown
                           uint64_t* out_create_time,       // FILETIME as u64
                           char* out_image_path, size_t out_image_path_len,
                           char* out_signer_subject, size_t out_signer_subject_len,
                           uint8_t* out_signed);            // 1 = chain-verified signed
```

Returns `false` if the pid is not currently tracked (unknown / exited). Any
out-pointer may be NULL. **Use this to get the `(sequence_number, create_time)`
pair for a response call** — the event header only carries
`actor_sequence_number`, not `create_time`.

### 4.5 Get a verdict

```c
bool evaluate_access_windows(uint32_t actor_pid,
                             uint32_t target_kind,   // 1 = file path, 2 = registry key path
                             const char* target_id,  // UTF-8; for kind 1 a WIN32 path (see gotcha)
                             uint32_t* out_verdict,
                             char* out_reason, size_t out_reason_len);
```

| `out_verdict` | meaning | agent action |
|---:|---|---|
| 0 | `NOT_PROTECTED` | ignore |
| 1 | `AUTHORIZED` | ignore |
| 2 | `UNAUTHORIZED` | protected, actor signer not in the owner set (or unsigned) → **respond** |
| 3 | `UNKNOWN_ACTOR` | protected, actor not yet resolved → **retry** after ~100–300 ms |

Pure decision, no side effects.

> **Gotcha:** for `target_kind = 1`, core resolves the path to `(vol, frn)` by
> `CreateFileW`-ing it, so it needs a **Win32 path** (`C:\Users\...\id_rsa`),
> **not** the `\Device\HarddiskVolumeN\...` path from the `FileCreate` event.
> The agent already knows which protected file the event hit (basename match) —
> pass the Win32 path from its own config record. (A future core change may
> normalise device paths here; today it does not.)

### 4.6 Respond (WS5)

```c
bool set_response_enforcement_windows(uint8_t enabled);   // DISARMED by default

bool suspend_process_windows  (uint32_t pid, uint64_t expected_seq, uint64_t expected_create_time);
bool resume_process_windows   (uint32_t pid, uint64_t expected_seq, uint64_t expected_create_time);
bool terminate_process_windows(uint32_t pid, uint64_t expected_seq, uint64_t expected_create_time);
```

- **No-op returning `false` until `set_response_enforcement_windows(1)`.**
- Each call re-resolves the pid and **refuses** unless the live identity
  matches `expected_seq` **or** `expected_create_time` (needs at least one
  non-zero side to match — this is the PID-reuse guard). Pass the pair from
  `resolve_actor_windows`; passing `actor_sequence_number` from the event
  header alone (with `create_time = 0`) also works if the sequence number is
  non-zero.
- Best-effort, usermode: cannot touch a PPL-protected target; a very fast
  single read can complete before a suspend lands (that's what the WS7 guard
  is for). `resume` is for false-positive recovery.

### 4.7 ABI check + sensor health (WS6)

```c
// call once at load time; assert against the agent's own struct sizes
bool telemetry_abi_windows(uint32_t* out_event_size,     // == 1590
                           uint32_t* out_header_size);   // == 30

bool get_telemetry_stats_windows(uint64_t* out_events_processed,
                                 uint64_t* out_events_lost,      // > 0 => consumer fell behind
                                 uint64_t* out_buffers_written,
                                 double* out_p50_ms, double* out_p95_ms,
                                 double* out_p99_ms, double* out_max_ms);
```

Poll periodically. `events_lost > 0` means the ETW session dropped events —
surface it as a degraded-sensor alert.

### 4.8 Native-module audit (interim hardening layer 3)

```c
int32_t list_process_modules_windows(uint32_t pid, char* out, size_t out_len);
```

Enumerates `pid`'s loaded modules; for each, resolves the backing file's
Authenticode signer through core's shared cache (**with the WS3 catalog-signing
fallback** — do not reimplement this in Rust, or every catalog-signed system
DLL reads as unsigned). Writes `"<full_path>\t<signer>\n"` per module (signer
empty = unsigned/untrusted/unresolved), truncates cleanly if `out` fills.
Returns the total module count (may exceed what was written), or `-1`.

Call from a worker — a first audit of a plugin-heavy process runs many
`WinVerifyTrust` calls. Not serialised against the rest of the FFI.

**Agent owns the policy:** which publishers are acceptable for this owner
process, and the **carve-out** — for Electron / .NET / JVM / browser processes
an unsigned-module finding is noise, fall back to owner-set + lineage only.

### 4.9 Registry (present but DORMANT in the reactive profile)

`add_protected_registry_key_windows`, `add_registry_key_owner_signer_windows`,
`is_authorized_registry_signer_windows`, `evaluate_access_windows` with
`target_kind = 2` — all still exported and functional as an in-memory store,
but the reactive profile **does not enable the Kernel-Registry ETW provider**,
so nothing feeds them live. Registry-persistence monitoring is the agent's job
now (snapshot + diff the persistence keys). `TaskRegistered` events still cover
scheduled-task persistence *with* the actor.

### 4.10 Self-update / process-integrity gate — NO-OP TODAY

`flag_process_injected_windows` / `clear_process_flag_windows` /
`is_process_clear_windows` / `is_authorized_self_update_windows` — exported but
inert: the injection-detection feed (ETW-TI) is PPL-gated and not wired.
`is_process_clear_windows` always returns `true`. Safe to call; don't rely on
it for a security decision yet.

---

## 5. The reactive loop (reference)

```
on TelemetryEvent ev:
    match ev.header.event_type:

      ProcessCreate | ProcessStop:
          update the agent's own process tree / lineage markers

      FileCreate:
          let dev_path = ev.details.file_create.file_path        // \Device\...
          let rec = agent.protected_files.match_by_basename_or_suffix(dev_path)?  // else ignore
          let pid = ev.header.pid
          loop up to ~1 s:
              evaluate_access_windows(pid, 1, rec.win32_path, &verdict, &reason)
              match verdict:
                0 | 1 -> break                     // not protected / authorised
                3     -> sleep 150 ms; continue     // UNKNOWN_ACTOR, retry
                2     ->                             // UNAUTHORIZED
                    let (seq, ct, ...) = resolve_actor_windows(pid)?
                    // policy: suspend first (recoverable), or terminate outright
                    suspend_process_windows(pid, seq, ct)
                    log alert; break

      FileRename | FileDelete:
          same match; treat as tamper with a protected file

      TaskRegistered:
          persistence via scheduled task; ev.header.pid is the installer.
          check against the agent's persistence policy; respond if unauthorised

      NetworkConnect | NetworkAccept:
          maintain per-pid "touched internet + which IPs" cache

      DpapiOperation:
          "this process used DPAPI at least once" signal (once per lifetime).
          correlate ev.header.pid against a credential-store owner policy if desired
```

Flagship files under `add_file_guard_windows` are handled inside core — the
opener is already suspended by the time the agent sees the `FileCreate`. The
agent should still process the event (log, confirm, maybe terminate).

---

## 6. Interim hardening (agent-side policy)

Three layers that raise the bar between the MVP owner-set check and the
eventual driver. All the *policy* lives in the agent; core provides the
mechanism.

### Layer 1 — tight per-category owner sets

Each protected resource's owner set (`add_resource_owner_signer_windows`)
contains the **specific vendor subject** — `"AgileBits, Inc."`, `"Google LLC"`,
`"Amazon.com Services LLC"` — **never `"Microsoft Windows"` broadly**. Then
every LOLBin (`esentutl.exe`, `reg.exe`, `certutil.exe`, `powershell.exe` — all
signed `"Microsoft Windows"`) is simply not on any allowlist. Microsoft
*applications* sign as `"Microsoft Corporation"` — a different subject — so
`msedge.exe` can be allowlisted for the Edge cookie DB without letting a single
LOLBin in.

*The one category that must include `"Microsoft Windows"`* is SSH keys (OpenSSH
ships in Windows; `ssh.exe` is `"Microsoft Windows"`). For that category only,
keep a small **file-copy-LOLBin image-name denylist** (`esentutl`, `certutil`,
`extrac32`, `expand`, `makecab`, `findstr`, `print`, `replace`, `diantz`, `reg`)
— ~10 entries, stable — and treat a match as unauthorised regardless of signer.

Core support: complete. `category` in `add_protected_resource_windows` is an
opaque `u32` core stores and never interprets — the category→signer-set mapping
is entirely yours.

### Layer 2 — lineage

Any process descended from a script host (`wscript`, `cscript`, `powershell`,
`mshta`, a macro-spawned `cmd`) touching a credential resource is unauthorised
regardless of its own signature.

Build the tree from `ProcessCreate` events (`child_pid`, `real_parent_pid`,
`child_sequence_number`, `parent_sequence_number`), keyed on
`(pid, sequence_number)`. **Stamp a persistent marker** when a process is first
seen as (or descended from) a script host, and propagate it to every descendant
at creation — do **not** re-walk `real_parent_pid` lazily at check time.

Caveat: `real_parent_pid` is ETW's `ParentProcessID`, which is **spoofable**
(`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`). Commodity malware doesn't bother; the
unspoofable source (`CreatingThreadId`) needs the Phase 7 driver.

### Layer 3 — native module-signer audit

When a process passes the owner-set check, audit its loaded native modules via
`list_process_modules_windows` (§4.8). Any module not signed by a publisher you
trust for this owner process ⇒ treat the access as compromised (sideloaded DLL
/ search-order hijack / `SetWindowsHookEx`).

**Carve-out:** skip this entirely for Electron / .NET / JVM / browser processes
— they load a mess of components and JIT into private memory; an unsigned-module
finding there is noise. Detect the runtime from the module list itself
(`coreclr.dll`, `clr.dll`, `jvm.dll`, `node.dll`, `*\Chrome*`, an Electron
`resources\app.asar`) and fall back to owner-set + lineage for those.

---

## 7. What core does NOT do

- Parse any config. The agent loads `protect-community/configs/antitheft/` and
  pushes entries via the setters above.
- Make the response *decision*. `evaluate_access_windows` returns a verdict;
  the agent decides suspend vs terminate vs alert-only.
- Registry-persistence monitoring in the reactive profile (agent's job).
- Block at the kernel level, resist being killed, or see PPL-protected process
  internals — all need the driver / an ELAM cert (`WINDOWS_COVERAGE_PLAN.md`).
- DPAPI *plaintext*-boundary enforcement — core sees the "used DPAPI" signal
  but there is no "is this process allowed to decrypt store X" gate yet.

---

## 8. ABI safety

The event struct is shared source with **no version field**. Rules:

1. Build the agent's `TelemetryEvent` from the *same* `telemetry.h` (or a
   hand-kept `#[repr(C, packed)]` mirror that is diffed in CI).
2. `const_assert!(size_of::<TelemetryEvent>() == 1590)` and
   `size_of::<TelemetryHeader>() == 30`. Core enforces the same with
   `static_assert` in `telemetry.h` — a drift on either side fails to build.
3. **At load time**, call `telemetry_abi_windows(&event_size, &header_size)`
   and assert both match the agent's struct sizes before reading the pipe.
   This catches an agent linked against a stale header vs a newer DLL.
4. Any change to `telemetry.h` (new field, new detail struct larger than
   `ProcessCreateDetails`) is a breaking change — rebuild both sides together
   and update the `static_assert` numbers here and in `telemetry.h`.

## 9. Config → registration checklist

For each protected file in config:

- [ ] resolve `(volume_serial, frn)` from the path
- [ ] `add_protected_resource_windows(vol, frn, category)`
- [ ] `add_resource_owner_signer_windows(vol, frn, signer)` for each allowed vendor
- [ ] `add_telemetry_path_filter_windows(win32_path)`
- [ ] if flagship: `add_file_guard_windows(win32_path)`
- [ ] keep the mapping `basename/frn → {win32_path, category, owner signers}` in the agent for the reactive loop

Then once: `set_response_enforcement_windows(1)` (or leave disarmed for a
detect-only rollout).
