# Windows coverage plan for `core/` — handoff for a Windows-side session

This file was written on Linux, where none of this can actually be built, run, or driver-verified. It exists so a Claude Code session running on a real Windows machine can pick this up and execute it with real build/test feedback, instead of starting from scratch or re-discovering the bugs below by hand.

**Read `kinnector.dev/antitheft/antitheft.md` first** (specifically §3 "Enforcement layer" Windows subsection, §4 "Storage-ownership subsystem," and §7 "Config & rule domain") — that's the source design doc this plan implements, and it carries the full technical rationale for *why* each mechanism below is designed the way it is: the Windows object-model gaps (handle duplication/inheritance, section-object mapping, raw-volume/VSS bypass, path aliasing), the APC-vs-remote-thread-vs-`SetThreadContext` injection analysis and why `ObRegisterCallbacks`-based handle-right restriction is the primary defense, why ALPC has no general blocking framework, why DPAPI is the *real* decryption boundary for most Windows credential stores (not the file itself), and — most load-bearing for this plan — why lineage propagation must key off `PS_CREATE_NOTIFY_INFO.CreatingThreadId` and never `ParentProcessId` (the latter is exactly the field `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` parent-PID-spoofing corrupts). This file doesn't repeat that reasoning — it's the execution plan, not the design doc.

## Verified current state (confirmed by direct file reads, not just a survey — re-verify anyway before relying on line numbers, the code may have moved since this was written)

- **`etw_consumer.cpp`** (511 lines) is the only real Windows collector today. Three ETW providers, user-mode only, no kernel driver involved:
  - `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`) — ProcessCreate (event ID 1), ProcessStop (2), ImageLoad (5) only.
  - `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`) — FileCreate (12) and FileIORead (15) only. No write/rename/delete.
  - `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`) — TcpIp/Connect (12) only. No listen/accept/UDP.
  - `ProcessCreateDetails` is populated from TDH's `ProcessId`/`ParentProcessId` properties at lines 337-338 — **PID only, `ProcessSequenceNumber` is never read**.
  - `TelemetryHeader.timestamp_ns` (line 323) is `event->EventHeader.TimeStamp.QuadPart * 100ULL` — the ETW event's own arrival timestamp, not a process creation time.
- **`driver_helper.h`** (13 lines) is a total no-op stub: `Initialize()`/`Start()` hardcode `return true`, `Stop()` is empty. `driver_helper.cpp` is just an `#include`. **Zero kernel-mode code exists anywhere in the workspace** — repo-wide search for `DriverEntry`/`FltRegisterFilter`/`ObRegisterCallbacks`/`PsSetCreateProcessNotifyRoutine`/`CmRegisterCallback` across `core`, `core-pro`, `warden*`, `antitheft-agent*`, `kinnector-config` returned zero matches. There is also no WDK/driver-toolchain reference anywhere (no `.sln`, `EWDK`, `signtool`, `INF2CAT` usage) — this is fully greenfield.
- **`../../include/kinnector/telemetry.h`**: `TelemetryHeader.sequence_number` is a global monotonic *event* counter across the whole telemetry stream, not a per-process identity. `ProcessCreateDetails` has only `child_pid`/`real_parent_pid` (plus image path/command line) — no sequence-number or create-time field of any kind.
- **`clipboard_helper.cpp`** (13 lines) is a dead stub — its comment claims it registers a clipboard listener and forwards to a named pipe; it does neither (just a bare `GetMessage` loop). The actual working clipboard listener lives entirely outside `core/`, in a separate Rust binary: `antitheft-agent/src/clipboard_helper.rs` (built as `antitheft-clipboard-helper`), which does real `AddClipboardFormatListener`/`GetClipboardData` work and writes ad-hoc JSON to its own pipe (`\\.\pipe\kinnect-clipboard-<session_id>`). **Nothing in `antitheft-agent` currently reads that pipe** — confirmed via grep, no `clipboard`/`kinnect-clipboard` references in `lib.rs`/`control.rs`. The pipeline is disconnected end-to-end; `ClipboardWriteDetails` in `telemetry.h` is unpopulated dead schema on Windows today.
- **`antitheft-agent/src/heuristics.rs:412-414` and `:553-555`** (confirmed via grep): build `ProcessKey { pid, start_time: 0 }` with the literal comment `// start time wild-card for simplicity in lookup`. Since `core` never emits anything better than an ETW event-arrival timestamp for `start_time` in the first place, this wildcard means `children_map` lookups are effectively **PID-only** despite `ProcessKey` including `start_time` in its `Hash`/`Eq` — a real, already-half-acknowledged PID-reuse vulnerability in the current lineage tracking.
- A cross-platform PPID-spoof heuristic already exists at `heuristics.rs:387-407` (not `#[cfg]`-gated) — compares kernel-reported `real_parent_pid` against the pid the event was attributed to, demotes to untrusted + fires `ppid_spoof` on mismatch. Reasonable foundation, **but on Windows it trusts ETW's `ParentProcessId` property**, which per the design doc's `PS_CREATE_NOTIFY_INFO` analysis is plausibly the same metadata field `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`-based spoofing corrupts. This needs explicit validation on a real Windows box — don't assume either way, and don't ship a claim that this heuristic is spoof-proof until it's actually tested against a PPID-spoofing PoC.
- `core`'s existing FFI surface (`../../include/kinnector/ffi.h`, `../../ffi.cpp`) is almost entirely BPF/Linux-shaped (`add_sensitive_inode`, `update_process_threshold`, BPF map ops) and no-ops on Windows. New Windows work needs its own FFI entry points, not reuse of these.
- `warden`/`wardend` is Linux-only (no `#[cfg(windows)]` anywhere in `warden/src`, `build.rs` hardcodes Linux paths/libs). **`antitheft-agent` is the real Windows consumer** of `core`'s telemetry — its Windows-side named-pipe IPC (`src/ipc.rs`, via `tokio::net::windows::named_pipe`) is a real, working ABI-compatible pairing with `core`'s `windows_ipc.cpp` today. Any new event type added to `core` needs a matching addition on the `antitheft-agent` side to actually be consumed — telemetry with no consumer is exactly the clipboard bug above, don't repeat that pattern.
- `core`'s Linux side (`../linux/`), for comparison, already keys everything on a `pid + start_time` compound key throughout its BPF map surface (`UpdateMapEntry(BpfMapType, pid, start_time, value)` etc.) — i.e. Linux already has the anti-PID-reuse discipline Windows currently lacks. Use that as the pattern to match, not reinvent.
- `core/README.md` claims "parent-child inheritance tracking" and full file-op coverage as if already true on Windows — both are aspirational relative to the code above. This plan is what actually closes that gap; update the README once each phase actually lands, don't leave it overclaiming.

## Phase 1 — Fix the disconnected clipboard pipeline

- Implement `clipboard_helper.cpp` for real: `AddClipboardFormatListener` + `WM_CLIPBOARDUPDATE` handling, populate `ClipboardWriteDetails` (already in `telemetry.h`), send through the standard `TelemetryEvent`/IPC pipe — not a separate side-channel.
- Once verified working end-to-end, retire `antitheft-agent/src/clipboard_helper.rs` and the `antitheft-clipboard-helper` binary/pipe so there's one clipboard path instead of one dead and one orphaned.
- Serves the "software wallets" and "passwords" product categories directly — clipboard-hijacking/address-swap detection depends on this.
- **Test**: trigger a clipboard write on the test machine, confirm the event arrives through `antitheft-agent`'s existing IPC consumption path end to end.

## Phase 2 — Fix process-lineage keying at the ETW layer

- Extend the Kernel-Process ProcessCreate TDH parsing in `etw_consumer.cpp` to also read `ProcessSequenceNumber` and `ParentProcessSequenceNumber` (present on the modern Kernel-Process ProcessStart schema as a spoof/reuse-resistant per-boot process identifier — verify field names against the current OS build's manifest via `tdh.h`/`wbemtest`/`logman query providers` rather than assuming they're named exactly this on every Windows version).
- Add `uint64_t child_sequence_number` / `uint64_t parent_sequence_number` to `ProcessCreateDetails` in `telemetry.h`, threaded through the packed-union ABI.
- Fix the confirmed `start_time: 0` wildcard at `heuristics.rs:412-414` and `:553-555` to use the real sequence number instead.
- Build the persistent lineage-marker table on top of the now-solid composite key (root-mark on package-manager-binary match against the config domain, propagate to children at process-create time — never re-derived later by walking mutable ancestry — prune on process-stop). Reasonable to keep in Rust (`heuristics.rs` already owns `ProcessKey`/`children_map`), since `core`'s job is delivering trustworthy identity, not owning policy state.
- **State explicitly in commit messages/docs, don't let this get oversold**: this ETW-based mechanism is an interim source. It's a real improvement over today's PID-only/wildcarded state, but only Phase 7's driver-based `CreatingThreadId` capture is actually spoof-proof against `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`-style attacks.
- **Test**: spawn a process, kill it, spawn a new one that reuses the same PID (or simulate this deterministically), assert the lineage table does not misattribute the new process to the old one's lineage — the direct regression test for the bug being fixed. Also test against a real parent-PID-spoofing PoC to characterize (not necessarily fully close, that's Phase 7) how the existing `heuristics.rs:387-407` heuristic behaves.

## Phase 3 — Complete ETW-only telemetry coverage

All detection-only (ETW can't block), all currently missing despite `telemetry.h` already having matching structs:

- Remaining Kernel-File event IDs for write/rename/delete-via-SetInformation — **validate the exact event IDs against the current Windows version's manifest at implementation time**, don't hardcode from memory or copy IDs from a different provider version.
- `Microsoft-Windows-Kernel-Registry` for registry read/write visibility (`RegistryWriteDetails` already exists in `telemetry.h`, unpopulated on Windows today).
- Fuller Kernel-Network coverage: listen/accept, UDP.
- `Microsoft-Windows-TaskScheduler` provider + Run-key-adjacent registry path coverage, for the supply-chain "persistence write" detection category.
- **Test**: exercise each event type directly (create/rename/delete a file, write a registry value, open a listening socket, register a scheduled task) and confirm each is captured, correctly typed, and forwarded through IPC.

## Phase 4 — ETW-TI integration

- Enable `Microsoft-Windows-Threat-Intelligence` for `VirtualAlloc(Ex)`/`VirtualProtect(Ex)`/`WriteProcessMemory`/`SetThreadContext`/`QueueUserAPC`/remote-thread-creation visibility. This is what makes APC injection, remote-thread injection, and memory-protection-flip techniques visible *at all* — currently zero Windows telemetry exists for any of them, despite `MemoryProtectDetails`/`PtraceAttachDetails`-equivalent schema already existing.
- **Validation spike required before building further on this**: ETW-TI access is historically more restricted than ordinary kernel providers (often gated behind PPL/antimalware-signing-level trust). Confirm `antitheftd` can actually consume it on a real machine before committing engineering time to features that assume it's available.
- Detection only — the actual *prevention* of injection is Phase 7's `ObRegisterCallbacks` work. This phase is the interim/complementary visibility layer and stays valuable as a detection backstop even after Phase 7 ships.
- **Test**: run a controlled, benign injection-technique PoC (e.g. `QueueUserAPC` into a disposable test process you own) and confirm the event is visible and correctly attributed.

## Phase 5 — Canonical resource identity + config-domain wiring

- Build a canonical-resource-identity resolution utility (volume serial + NTFS File Reference Number) in this directory — needed both by any interim detection logic now and by the Phase 7 driver later.
- Wire `core` to the new `kinnector-config`/`protect-community/configs/antitheft/` policy domain — `core` currently has zero dependency on `kinnector-config` anywhere (verified, no references in the repo). Provider/keyword/protected-resource selection is entirely hardcoded today; this phase makes it config-driven and hot-reloadable, matching the discipline already established for Warden.
- **Test**: create a hardlink or NTFS junction to a tracked file, confirm it resolves to the same canonical identity as the original — the direct test for the path-aliasing gap this closes.

## Phase 6 — DPAPI monitoring

- Add `Microsoft-Windows-Crypto-DPAPI` provider consumption, attributing `CryptUnprotectData`/`NCryptUnprotectSecret` calls to protected credential stores per the config domain.
- Detection only. Attribution precision (which store's blob is actually being touched) needs its own validation spike — don't ship a claim of guaranteed attribution before this is confirmed working on a real machine.
- **Test**: call `CryptUnprotectData` from a disposable test process against a blob associated with a tracked credential store, confirm correct attribution.

## Phase 7 — The kernel-mode driver

The large item: real blocking, and the only fully spoof-proof lineage source. Build out `driver_helper.h`'s stub into an actual WDK minifilter project (new subdirectory, e.g. `driver/`), with its own signing/toolchain workstream running in parallel to everything above:

- WDK project setup, EV code-signing certificate procurement, Microsoft Hardware Dev Center / WHCP submission process, a Driver Verifier-based stress-testing loop — this has its own timeline, independent of `core`'s normal release cycle. Start this workstream early; it's very likely the long pole for the whole plan.

Build incrementally — each numbered step below gets its own build + Driver Verifier + stress-test cycle before the next one starts. Do not attempt this as one large change; kernel-mode code is exactly where big-bang delivery causes BSODs and, worse, security holes in the thing meant to prevent them.

1. Driver loads, does nothing harmful — prove the toolchain end-to-end first.
2. `IRP_MJ_CREATE` gate against the config-driven protected-resource list, using Phase 5's canonical-identity resolution (reimplemented as kernel-safe code — user-mode STL can't cross into kernel context directly, needs a kernel-safe subset).
3. `CmRegisterCallbackEx` for registry-key protection, including the hive-file-as-plain-file coverage tie-in (protect the underlying `NTUSER.DAT`-style files via the same IRP_MJ_CREATE gate, not just live registry API calls).
4. `PsSetCreateProcessNotifyRoutineEx2`, keyed on `(PID, PsGetProcessCreateTimeQuadPart(EPROCESS))`, propagating the lineage marker via `PS_CREATE_NOTIFY_INFO.CreatingThreadId` — **never `ParentProcessId`**. This is what supersedes Phase 2's ETW-based interim mechanism as the authoritative source. Validate the exact `PS_CREATE_NOTIFY_INFO` field behavior against the current WDK header before relying on it — don't assume the field layout described in the design doc is exactly right without checking.
5. `ObRegisterCallbacks` restricting `PROCESS_VM_WRITE`/`THREAD_SET_CONTEXT`/`PROCESS_VM_READ`/handle-duplication rights on configured owner processes, unless the requester is on a short explicit allowlist. This is the actual prevention layer for APC injection, remote-thread injection, `SetThreadContext` hijacking, and cross-process memory scraping — closes what Phase 4's ETW-TI can only detect, not stop. Note: File-object-type support for `ObRegisterCallbacks` (needed for handle-duplication coverage on protected files, not just Process/Thread) is unverified from the design doc's own admission — confirm this works before relying on it, and have a fallback plan (e.g. detect-and-revoke via periodic handle-table audit) ready if it doesn't.
6. Raw-volume/physical-disk (`\\.\C:`, `\\.\PhysicalDriveN`) coarse allowlist gate — fold into this same driver rather than a separate project.
7. Driver self-protection: PPL (Protected Process Light) status where achievable, tamper-protection against service stop/driver unload by anything less than what Defender requires of itself. State plainly in any accompanying docs that a fully privileged BYOVD/kernel-level attacker remains a residual risk, not something this closes — don't imply otherwise.

**Test at every sub-step, before moving to the next**: `verifier.exe` (Driver Verifier) clean run, plus stress testing under heavy process-creation and file-I/O churn. No sub-step ships to a real test machine, let alone anywhere near a production build, without this.

## Cross-cutting note for whoever picks this up

Every phase above that adds new `core`-side telemetry needs a paired, explicitly-scoped change in `antitheft-agent` (or the future unified `antitheftd`, see `antitheft.md` §2 for the target component structure — there is no OSS/Pro split for this product, see `antitheft.md` §8) to actually consume the new event type. Treat `core/`-side changes as incomplete until that pairing exists — the clipboard bug documented above is the existing proof of what happens when telemetry ships with no consumer.
