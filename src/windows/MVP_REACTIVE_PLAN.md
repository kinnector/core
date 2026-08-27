# Windows reactive-MVP plan for `core/`

Scope: **`core` only**, Windows side. Target is a shippable, driver-less, PPL-less
build that consumes everything ETW gives under ordinary elevation and can *act*
on an unauthorized process touching a protected credential resource — fast enough
to prevent or interrupt real-world theft, not just log it after the fact.

## Status (updated 2026-08-27)

| WS | State | Test |
|----|-------|------|
| 1 — actor identity spine | **DONE, verified** | `test_actor_identity` (elevated) |
| 2 — registry protected-resource store | **DONE, verified** | `test_registry_protection` (part 1 unpriv, part 2 elevated) |
| 3 — catalog-signing fallback | **DONE, verified** | `test_catalog_signing` (unpriv) |
| 4 — `evaluate_access_windows` | **DONE, verified** | `test_reactive_e2e` (elevated) |
| 5 — response primitives (suspend/resume/terminate) | **DONE, verified** | `test_reactive_e2e` (elevated) |
| 6 — detection-latency reduction | **DONE** (FlushTimer=1, system-time clock, 64KB×32–128 buffers, ImageLoad verification moved fully async with a real-vs-warm priority queue so a DLL-load flood can't starve identity resolution, image-path resolved synchronously in `OnProcessStart`, `StartTrace` retry on `ERROR_ALREADY_EXISTS`, per-session EventsLost + emit-latency percentiles logged at Stop) | measured in every elevated ETW test; full suite 7×13 green |
| 7 — oplock synchronous hold | **DONE, verified** (see WS7 notes below) | `test_file_guard` (elevated) |

**WS6 gate result (measured on this machine, `test_actor_identity` under a 120-process spawn stress):**
`EventsLost=0`, emit latency **p50 ≈ 95–100 ms, p95 ≈ 120–200 ms, p99 ≈ 200–220 ms, max < 1.1 s**
*when the machine is near-idle*. **Under real load** (a dev box at ~50% CPU, ~6k
ETW events/s) the same test shows **p50 ≈ 1–3 s** — the main consumer's
`ProcessEvent` (TDH parse + dispatch) runs inline on the single ProcessTrace
callback thread with no drain thread, and can't keep up. Tier A degrades
accordingly under load. **WS7 works around this with its own single-provider
ETW session** (see WS7 notes); a proper drain thread for the main consumer is a
worthwhile WS6 follow-up.
Either way: a single `CreateFile`+`ReadFile`+exit on one file finishes in
< 10 ms — Tier A cannot beat that. **WS7 (oplock hold) is required for a hard
"prevents theft" claim on the single-file case**; the flagship at-rest files
(SSH keys, wallet/vault files) are exactly that case.

Files added by WS1–6: `process_registry.{h,cpp}`, `win_paths.{h,cpp}`,
`response.{h,cpp}`, `ProtectedRegistryStore` + `CanonicalizeRegistryKey` in
`resource_identity.{h,cpp}`, catalog path + `PeekSignerCache`/`WarmSignerCache` in
`authenticode.{h,cpp}`, `actor_sequence_number` on `TelemetryHeader`, new FFI in
`ffi.{h,cpp}`. **ABI: `TelemetryHeader` grew — the antitheft-agent pipe consumer
must be rebuilt (the "core before Rust" follow-up).**
Added by WS7: `file_guard.{h,cpp}`, `test_file_guard.cpp`, `add_file_guard_windows`
/ `remove_file_guard_windows` FFI, a synchronous creation-time recheck in
`ResponseEngine::Act`.

This is deliberately narrower than `WINDOWS_COVERAGE_PLAN.md` (which is the full
driver + ETW-TI design). It is the "get something people can actually run and
that actually stops theft" milestone, to be superseded by the driver later.

## Goal / non-goals

**Goal:** an unauthorized process that opens/reads/writes a registered protected
resource (credential file, credential-bearing or persistence registry key) is
identified with a reuse-safe identity and can be suspended/terminated by `core`
on the agent's instruction, within a latency budget small enough to matter.

**Explicitly out of scope for this milestone** (not "never", just not now):

- Driver / minifilter / any kernel-mode code.
- ETW-TI / Antimalware-PPL / injection visibility (`WINDOWS_COVERAGE_PLAN.md`
  Phase 4, blocked on ELAM cert).
- Driver / service self-protection, anti-kill, tamper resistance
  (`WINDOWS_COVERAGE_PLAN.md` Phase 7 step 10). We do not care if we get killed
  yet — popularity first, hardening later.
- Config-file loading/parsing — stays `antitheftd`'s job, `core` only exposes
  FFI setters (same boundary as Phase 5 / `add_protected_resource_windows`).
- The `antitheft-agent` / `antitheftd` consumer rework. WS1 forces an eventual
  ABI bump on that side; that work is tracked separately ("core before Rust").

## No-driver / no-PPL compatibility audit

Every API this plan uses runs in an ordinary elevated usermode process. The one
true prerequisite is **elevation — ideally SYSTEM via a Windows service** (not a
driver, not PPL). Per-workstream:

| WS | OS surface used | Driver? | PPL? |
|---|---|---|---|
| 1 | `Microsoft-Windows-Kernel-Process` ETW (already consumed today); `NtQuerySystemInformation(SystemProcessInformation)` + `QueryFullProcessImageNameW` + `GetProcessTimes` for startup seed; `WinVerifyTrust` on a worker thread | no | no |
| 2 | `Microsoft-Windows-Kernel-Registry` ETW (Phase 3, ordinary elevation); string normalization + well-known-SID lookup | no | no |
| 3 | `CryptCATAdminAcquireContext2` / `CryptCATAdminCalcHashFromFileHandle2` / `CryptCATAdminEnumCatalogFromHash` / `WinVerifyTrust` (crypt32 + wintrust) | no | no |
| 4 | pure in-process composition of WS1+WS2+Phase 5 | no | no |
| 5 | `OpenProcess(PROCESS_SUSPEND_RESUME\|PROCESS_TERMINATE)` + `NtSuspendProcess` / `TerminateProcess` (fallback: `Thread32First` + `SuspendThread` loop) | no | no |
| 6 | `EVENT_TRACE_PROPERTIES.FlushTimer` (usermode ETW session config); real-time consumption as today | no | no |
| 7 | `DeviceIoControl(FSCTL_REQUEST_OPLOCK)` with `OPLOCK_LEVEL_CACHE_READ\|CACHE_HANDLE`, overlapped — a documented usermode filesystem primitive (Win7+); NTFS implements the kernel side, the requester is usermode | no | no |

**PPL-adjacent edges — limitations, not dependencies.** These do not stop the
plan from working without PPL; they are gaps in coverage that only a PPL/driver
build would close, and they are already in "Honest limitations":

- WS1 startup seed: `QueryFullProcessImageNameW` fails for the handful of
  PPL-protected processes (lsass with RunAsPPL, AV, some system processes). We
  fall back to `NtQuerySystemInformation`, which still returns image *name* +
  create time for every process including protected ones — only the full path
  may be missing for those. A stealer is never one of these processes.
- WS5 response: cannot suspend/terminate a PPL-protected target. Infostealers do
  not run as PPL (it requires an ELAM-signed cert), so the process we need to
  act on is always one we can open. A sophisticated attacker who obtains PPL is
  out of scope for this milestone regardless.
- WS7 hold: if a legit owner holds the flagship file open continuously with a
  restrictive share mode, `core` may be unable to arm the oplock — that file
  falls back to Tier A. Functional limitation, no PPL involved.

None of WS1–WS7 read another process's memory, intercept handle operations, or
touch `Microsoft-Windows-Threat-Intelligence` — the three things that would pull
in PPL or the driver.

## What "prevent" realistically means here

Two tiers, both in this plan:

- **Tier A — interrupt in flight (all protected resources).** Async ETW event →
  `core` evaluates → agent calls `suspend_process_windows`. Latency is ETW
  real-time delivery + parse + evaluate, targeted at sub-second with WS6.
  - Stops: multi-step stealers (enumerate → read many secrets → package →
    beacon), persistence installation, clipboard-swap malware, anything that
    takes more than the latency budget.
  - Does **not** guarantee stopping: a single `CreateFile`+`ReadFile`+exit
    against one non-guarded file that completes inside the budget.
- **Tier B — synchronous hold (small flagship set of at-rest files: SSH keys,
  wallet files, password-manager vaults).** Filesystem oplock on the file; a
  foreign open is held by the OS until `core` acknowledges. `core` uses that
  window to suspend the opener before its first read returns. Real "deny-ish"
  for the guarded set. WS7, gated on WS6 measurements.

Neither tier touches: PPL-protected target processes, kernel/BYOVD attackers, or
"read the encrypted blob, crack it offline" (we see the read; preventing it means
suspending before the read returns — Tier B only, guarded set only).

---

## WS1 — Actor identity spine  *(prerequisite for everything below)*

**Problem.** `TelemetryHeader` (`include/kinnector/telemetry.h`) carries `pid`
only. No creation-time / sequence number, so nothing downstream can key an actor
reuse-safely for a file/registry/network event; only `ProcessCreateDetails`
carries sequence numbers, and only for the child/parent of that one event. No
signer context on the actor either.

**Changes.**

1. `telemetry.h` — add to `TelemetryHeader`:
   ```c
   uint64_t actor_sequence_number;  // Kernel-Process ProcessSequenceNumber of
                                    // header.pid; 0 = unavailable (pre-existing
                                    // process, or older OS). Callers must not
                                    // treat 0 as a real sequence value.
   ```
   This shifts the offset of every `details` payload → an ABI break for the
   current `antitheft-agent` consumer. Acceptable now (that side is being
   reworked regardless, and the cross-cutting note in `WINDOWS_COVERAGE_PLAN.md`
   already says every new event needs a paired consumer change). Record the
   break in the commit message. If a schema-version constant exists anywhere,
   bump it.

2. New `src/windows/process_registry.{h,cpp}` — `ProcessRegistry`, an in-process
   `pid -> ActorInfo` map:
   ```
   struct ActorInfo {
       uint64_t sequence_number;   // 0 if pre-existing / unavailable
       uint64_t create_time;       // FILETIME, always populated
       std::wstring image_path;
       std::string  signer_subject; // "" until verified / if unsigned
       enum { Pending, Signed, Unsigned } signer_state;
   };
   ```
   - Populated from the `Microsoft-Windows-Kernel-Process` ProcessStart events
     already consumed in `etw_consumer.cpp` (image path + sequence number are in
     that event; create_time from the event timestamp or `GetProcessTimes`).
   - Pruned on ProcessStop.
   - **Bootstrap at startup**: enumerate already-running processes
     (`CreateToolhelp32Snapshot` / `NtQuerySystemInformation`), seed with
     `QueryFullProcessImageNameW` + `GetProcessTimes` creation time.
     `sequence_number = 0` for these; `create_time` is the composite key.
   - `std::mutex` (usermode, no IRQL concerns). Reads are hot — keep the lock
     narrow, copy the `ActorInfo` out.

3. Signer verification is **off the ETW callback thread**. On ProcessStart,
   enqueue the pid to a worker thread that runs the WS3 combined Authenticode
   check and fills `signer_subject` / `signer_state`. Cache by
   `(image_path, last-write-time)` so repeated launches of the same binary are
   one verification. Use no-network revocation (`WTD_REVOKE_NONE` or
   cache-only) for latency.

4. `etw_consumer.cpp` `ProcessEvent` — for every emitted event, look up
   `header.pid` in `ProcessRegistry` and set `header.actor_sequence_number`
   (best effort; leave 0 if unknown).

5. FFI (`ffi.h` / `ffi.cpp`):
   ```c
   KINNECTOR_API bool resolve_actor_windows(
       uint32_t pid,
       uint64_t* out_sequence_number, uint64_t* out_create_time,
       char* out_image_path, size_t image_path_len,
       char* out_signer_subject, size_t signer_subject_len,
       uint8_t* out_signed);   // 0 unsigned/pending, 1 signed
   ```
   No-op returning false on non-Windows.

**Test.** Spawn → kill → spawn a PID-reusing process; assert `resolve_actor` does
not return the dead process's identity for the new PID. Assert a signed binary
resolves a non-empty signer and an unsigned one resolves empty/unsigned.

---

## WS2 — Registry protected-resource store

**Problem.** `ProtectedResourceStore` (`resource_identity.h`) and its FFI
(`add_protected_resource_windows` etc.) are file-shaped: `(volume_serial,
file_reference_number)`. The MVP also protects registry-stored secrets and
persistence keys (`Run`, `RunOnce`, service keys, `Image File Execution
Options`). `RegistryWriteDetails.key_path` is already emitted by
`etw_consumer.cpp`; there is no store to match it against.

**Changes.**

1. `resource_identity.{h,cpp}` — registry-key canonical identity. No inode
   equivalent; the identity is the normalized path:
   - Resolve predefined roots to native form: `HKCU` → `\Registry\User\<SID>`,
     `HKLM` → `\Registry\Machine`, `HKU` → `\Registry\User`, etc.
   - Uppercase, collapse duplicate separators, strip trailing separator.
   - `std::wstring ResolveCanonicalRegistryKey(const std::wstring& input);`
   - ETW's `key_path` is already native (`\REGISTRY\MACHINE\...`); the FFI input
     from the agent may be `HKLM\...` form — normalize both through this.

2. New `ProtectedRegistryStore` (sibling class in `resource_identity.h`, same
   shape as `ProtectedResourceStore` but keyed on the canonical wstring):
   - Exact-match and **subtree-match** entries (protecting `...\Run` optionally
     covers new subkeys/values under it). Store a `bool subtree` per entry.
   - Per-entry signer allowlist, identical semantics to
     `ProtectedResourceStore::owner_signers_`.

3. FFI:
   ```c
   KINNECTOR_API bool add_protected_registry_key_windows(
       const char* canonical_key_path, uint32_t category, uint8_t subtree);
   KINNECTOR_API bool remove_protected_registry_key_windows(
       const char* canonical_key_path);
   KINNECTOR_API bool is_protected_registry_key_windows(
       const char* key_path, uint32_t* out_category);   // canonicalizes input
   KINNECTOR_API bool add_registry_key_owner_signer_windows(
       const char* canonical_key_path, const char* signer_subject);
   KINNECTOR_API bool remove_registry_key_owner_signer_windows(
       const char* canonical_key_path, const char* signer_subject);
   KINNECTOR_API bool is_authorized_registry_signer_windows(
       const char* key_path, const char* signer_subject);
   ```

**Test.** `HKCU\...\Run` and `\Registry\User\<SID>\...\Run` canonicalize to the
same identity. Subtree entry matches a child key; exact entry does not.

---

## WS3 — Catalog-signing fallback in `authenticode.cpp`

**Problem** (Phase 5 known gap, confirmed 2026-08-26). `VerifyAuthenticodeSignature`
only checks *embedded* signatures (`WTD_CHOICE_FILE`). Catalog-signed binaries —
most OS files, MSI-delivered binaries, some updaters — return `TRUST_E_NOSIGNATURE`
and are treated as unsigned. A product that suspends a legitimately-signed vendor
updater because its signature is catalog-based will not get popular. Also means
`ImageLoadDetails.is_signed` has been under-reporting.

**Changes.** In `authenticode.cpp`, when the embedded check returns
`TRUST_E_NOSIGNATURE`:

1. `CryptCATAdminAcquireContext2` (SHA-256) → `CryptCATAdminCalcHashFromFileHandle2`
   → `CryptCATAdminEnumCatalogFromHash` loop.
2. For each catalog hit, `WinVerifyTrust` with `WINTRUST_CATALOG_INFO`
   (`WTD_CHOICE_CATALOG`).
3. Extract the signer subject from the catalog signer cert, same as the embedded
   path.
4. Feed results through WS1's signer cache.

**Test.** `explorer.exe` still verifies via embedded; `notepad.exe` now resolves
a signer via catalog instead of `TRUST_E_NOSIGNATURE`; a bit-flipped copy of a
signed binary fails both.

---

## WS4 — `evaluate_access_windows` — one call for the consumer

**Problem.** Without this, the agent has to stitch WS1 + WS2 + Phase 5 together
itself. Keep identity-resolution and matching in `core`; the agent still owns the
rule store (it pushed the entries in) and owns the response decision.

**Change.** FFI:
```c
// target_kind: 1 = file path (UTF-8), 2 = registry key path (UTF-8)
// out_verdict: 0 = NOT_PROTECTED (not our concern)
//              1 = AUTHORIZED   (actor signer in the resource's allowlist)
//              2 = UNAUTHORIZED (protected, actor signer not allowed / unsigned)
//              3 = UNKNOWN_ACTOR(protected, actor identity not yet resolved)
KINNECTOR_API bool evaluate_access_windows(
    uint32_t actor_pid,
    uint32_t target_kind, const char* target_id,
    uint32_t* out_verdict,
    char* out_reason, size_t reason_len);
```
Pure function: canonicalize target → store lookup → if protected, resolve actor
(WS1) → check signer against that resource's allowlist. No side effects, no
policy, no config. The agent decides what `UNAUTHORIZED` warrants.

**Test.** Protected file + unauthorized actor → `UNAUTHORIZED`; + authorized
signer → `AUTHORIZED`; unprotected file → `NOT_PROTECTED`; actor still
`Pending` verification → `UNKNOWN_ACTOR`.

---

## WS5 — Reactive response primitives

**Problem.** `core` has no way to act on Windows without the driver.

**Change.** New `src/windows/response.{h,cpp}`, FFI:
```c
KINNECTOR_API bool set_response_enforcement_windows(uint8_t enabled); // default 0

// All three re-resolve pid in ProcessRegistry and REFUSE (return false) if the
// sequence number / create_time does not match expected_* — never act on a
// reused PID. No-op returning false unless enforcement is armed.
KINNECTOR_API bool suspend_process_windows(uint32_t pid, uint64_t expected_sequence_number,
                                           uint64_t expected_create_time);
KINNECTOR_API bool resume_process_windows (uint32_t pid, uint64_t expected_sequence_number,
                                           uint64_t expected_create_time);
KINNECTOR_API bool terminate_process_windows(uint32_t pid, uint64_t expected_sequence_number,
                                             uint64_t expected_create_time);
```
- `suspend` = `NtSuspendProcess` (via `OpenProcess(PROCESS_SUSPEND_RESUME)`);
  `terminate` = `TerminateProcess`; `resume` for false-positive recovery.
- **Default disarmed**, explicit `set_response_enforcement_windows(1)` required —
  matches `CLAUDE.md`'s "any function that can arm blocking must default to off."
- Dumb executors. The agent calls these after `evaluate_access_windows` returns
  `UNAUTHORIZED`. `core` owns execution + the reuse-safety guard; agent owns the
  decision.
- Header doc must state plainly: usermode, best-effort, racy; cannot touch
  PPL-protected targets; a fast single read may complete before the suspend
  lands (that's what WS7 is for).

**Test.** Suspend with correct sequence → target actually suspended (verify via
thread state). Suspend with stale sequence → refused. All primitives no-op while
disarmed.

---

## WS6 — Detection latency reduction

**Problem.** Default ETW real-time delivery can lag by seconds. If Tier A is
going to "prevent" anything it has to be sub-second.

**Changes** in `etw_consumer.cpp`:

1. Set `EVENT_TRACE_PROPERTIES.FlushTimer = 1` (1 s, the documented minimum) on
   the session.
2. `EventRecordCallback` must do **only** parse + enqueue. Signer verification
   (WS1), store matching, and any FFI callback happen on a separate drain
   thread. No `WinVerifyTrust`, no lock contention, no allocation storms on the
   callback thread.
3. Add an instrumentation counter: event-timestamp → callback-entry latency,
   log p50/p95/p99 at `Stop()`. Add `EventsLost` / `BuffersLost` from the trace
   stats to the same summary.
4. **Go/no-go gate for WS7:** if measured p95 end-to-end (event → agent has the
   verdict) is comfortably under the time a realistic stealer takes to open and
   drain one file, Tier A alone may be enough to ship and WS7 can wait. If not,
   WS7 is required for a credible "prevents theft" claim.

**Test.** Latency counters present and non-zero in the shutdown summary; a
synthetic file-touch is observed in the callback within the budget.

### WS6 event-volume reduction (2026-08-27) — partial, plus real per-type data

`ProcessEvent` still parses+dispatches inline on the one ProcessTrace callback
thread (no drain thread yet). Two things landed:

**1. Per-(provider, event-id) arrival counter**, logged at `Stop()` next to the
latency line. First real breakdown, from `test_actor_identity` (~113k events,
"full" profile, this machine):

| event | count | | event | count |
|---|---:|---|---|---:|
| Kernel-File **Create** (12) | **91,487** | | Kernel-Process ImageLoad (5) | 3,533 |
| Kernel-Registry **OpenKey** (2) | **36,044** | | Kernel-Process Image? (6) | 3,555 |
| Kernel-File Write (16) | 15,849 | | Kernel-Process Thread start/stop (3/4) | ~2,300 |
| Kernel-Registry CreateKey (1) | 1,393 | | Kernel-File **Read** (15) | **529** |

The assumptions going in were wrong: **File Create and Registry OpenKey are the
giants**; File Read is negligible; Write is mid. Cutting Read/Write/ImageLoad/
Thread removes ~22% of volume and the ImageLoad *burst*, but not the head of
the distribution.

**2. Selectable profile** — `set_telemetry_profile_windows(0|1)`, call between
`initialize` and `start`. `EtwConsumer::Profile::{Full,Reactive}`; `Full` is the
default and unchanged (Phase 1-3 collector tests use it). `Reactive` (the MVP's
profile — `test_reactive_e2e` / `test_file_guard` select it):

| provider | Full | Reactive |
|---|---|---|
| Kernel-Process | PROCESS+IMAGE+THREAD | **PROCESS only** |
| Kernel-File | CREATE+READ+WRITE+DELETE+RENAME | **CREATE+DELETE+RENAME** |
| Kernel-Network | IPv4+IPv6, all events | IPv4+IPv6, **`EVENT_FILTER_TYPE_EVENT_ID` → Connect+Accept only** |
| Kernel-Registry | CreateKey+OpenKey+SetValue | *unchanged* — see below |
| TaskScheduler / DPAPI / ETW-TI | *unchanged* |

**Schema cache — DONE 2026-08-27.** `s_schema` in `etw_consumer.cpp`: memoises
`TRACE_EVENT_INFO` keyed on the full `EVENT_DESCRIPTOR` layout-affecting fields
(provider GUID + Id + Version + Channel + Level + Opcode + Task — *not* Keyword).
Non-manifest schemas (`DecodingSource != DecodingSourceXMLFile`) get an empty
slot = "cold-parse forever". A 1/8192 canary re-parses a cached type and
`memcmp`s; mismatch → log + evict. `ProcessEvent` no longer calls
`TdhGetEventInformation` per event. **Measured: p50 dropped from ~1–3 s to
~65–170 ms at ~100k events (this machine); hit rate 99.99%; the canary caught a
real bug during dev — same (id,version) different Opcode sharing a slot — fixed
by widening the key.** 14/14 ctest + `test_file_guard` 8/8. Stats logged at
`Stop()`.

**Still open, in priority order:**
- **Drop Registry OpenKey (id 2) from Reactive** — 36k events, #2 source. Held
  back because SetValueKey path resolution chains off the OpenKey/CreateKey
  BaseObject→KeyObject cache; dropping OpenKey may leave SetValue-on-a-
  pre-existing-key with an unresolved path (→ missed match). Needs a reactive
  registry-protection test before this is safe.
- **Drain thread** — callback does `O(copy)` + enqueue; parse+dispatch on
  worker(s). Guarantees no `EventsLost`; only helps latency once the schema
  cache has raised per-event μ.
- Kernel-File Create path-prefilter in the consumer (match against the
  protected-resource + FileObject-tracked set before `should_emit`) — only
  worth it after the schema cache, since you still pay to receive+parse.

Accepted Reactive-profile gaps: file reads via a handle opened before the
engine/rule existed; DNS-over-UDP destinations; live ImageLoad feed (module
inventory is an on-alert scan per the WS8-style discussion).

---

## WS7 — Oplock synchronous hold for the flagship at-rest file set  *(gated on WS6)*

**Problem.** Tier A can't stop a single fast read. For SSH keys / wallet files /
vault files — rarely open, extremely high value — we want a real hold.

**Change.** New `src/windows/file_guard.{h,cpp}`:

1. For each guarded path, `core` opens a handle and arms an oplock:
   `FSCTL_REQUEST_OPLOCK`, `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`, level
   `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`, overlapped.
2. A foreign `CreateFile` on the path triggers an oplock break, delivered via
   the overlapped completion; the foreign open is held by the OS pending
   `core`'s acknowledgement.
3. In that window `core`:
   - The break carries **no requestor identity** — correlate by waiting
     (bounded, e.g. 500 ms) for the `Microsoft-Windows-Kernel-File` FileCreate
     ETW event for the same path, which carries the pid. Match → resolve actor
     (WS1) → `evaluate_access_windows`.
   - If `UNAUTHORIZED` and armed → `suspend_process_windows` the opener, then
     acknowledge the break. The opener resumes execution already suspended and
     never reads.
   - If `AUTHORIZED`, or the correlating ETW event doesn't arrive in budget, or
     enforcement is disarmed → acknowledge/downgrade immediately (**fail open** —
     never hang legitimate access).
4. Re-arm the oplock after every break.
5. FFI:
   ```c
   KINNECTOR_API bool add_file_guard_windows(const char* path);      // UTF-8
   KINNECTOR_API bool remove_file_guard_windows(const char* path);
   ```

**Caveats to document.** Only works while `core` holds the guarded file open
(not while a legit owner has it open exclusively). One handle per guarded file.
Legit-owner opens also break the oplock — the `AUTHORIZED` path must be fast.
Keep the guarded set tiny (target < 50 files). Fail-open on every uncertainty.

**Test.** `test_file_guard.cpp` — guarded file, an unauthorized "stealer" test
binary opens then reads it; assert the stealer is suspended with **0 bytes read**
at suspend time; assert an authorized reader is not delayed beyond a small bound.

---

### WS7 as built (2026-08-27) — differs from the sketch above in three ways the sketch's assumptions forced

**1. RWH oplock, not RH.** `OPLOCK_LEVEL_CACHE_READ | _WRITE | _HANDLE`. An RH
oplock (sketch) does **not** block a foreign *reader* — reads are compatible
with RH, so the reader sails through and we only get a notification after the
fact. Only the W level makes a foreign read *conflict*, and only a conflicting
op is held pending our ack. Confirmed empirically: with RH the stealer's read
completed; with RWH it is held. Downside: RWH also breaks on the *authorized*
opener's own `ReadFile` (which emits no Kernel-File CREATE event, so it can't be
correlated) — handled by the "vetted pid" fast-path (see 3).

**2. Dedicated correlation ETW session + synchronous identity.** The main
telemetry consumer has no drain thread — `ProcessEvent` (TDH parse +
dispatch) runs inline on the single ProcessTrace callback thread, and under
real load (~6k events/s on a busy box) it falls **1–3 s behind** (WS6's ~95 ms
was measured near-idle). At that lag, neither the FileCreate correlation event
nor the opener's ProcessStart (→ ProcessRegistry) arrives inside any sane hold
budget. So WS7 runs its **own** ETW session subscribed to Kernel-File CREATE
*only*. NOTE: CREATE turned out to be ~90 % of file-event volume, not ~1 % as
first assumed, so this session is *not* light — it needs 64 KB × 16–64 buffers,
a minimal single-`TdhGetProperty` callback, and a **1.4 s** correlation budget
(500 ms in the sketch) to stay reliable under load. Even then it's the fragile
spot; a proper schema cache would let it (and the main consumer) actually be
cheap. `FileGuardEnforce` resolves the opener **synchronously** —
`OpenProcess(QUERY_LIMITED_INFORMATION)` +
`QueryFullProcessImageNameW` + `GetProcessTimes` + `CachedVerifyAuthenticode` —
instead of via the lagged `ProcessRegistry`. `ResponseEngine::Act` gained a
synchronous `GetProcessTimes` creation-time recheck for the same reason (the
registry's create_time is ETW-timestamp-derived and never equals
`GetProcessTimes`' value, and a just-spawned opener isn't in the registry yet).
This also means WS7 does **not** call `evaluate_access_windows` — it re-implements
the same owner-set check synchronously. Kept identical on purpose; if the
owner-set semantics change, change both.
   *(The main consumer's missing drain thread is a real WS6 gap that also caps
   Tier A's reaction speed under load — worth its own follow-up.)*

**3. Correlation is a candidate list + "vetted pid" fast-path.** The break
gives no identity; multiple processes (real opener + AV real-time scan + …)
often create the file within ms. `FileGuard` collects **all** pids that fire a
CREATE for the path during the hold and hands the list to `FileGuardEnforce`,
which acts on the first *actionable* one (a protected AV process fails
`OpenProcess`/query and is skipped). After a decision, that pid is remembered
for `kVettedGraceMs` (4 s): subsequent breaks that correlate to it — or
uncorrelated breaks, which is what its own `ReadFile`s look like — are ack'd
immediately without re-holding. Plus a back-off after a run of uncorrelated
breaks so a hot file (AV rescan loop) isn't held for a full budget each time.

**Verified on this machine 2026-08-27** (`test_file_guard`, elevated, full
14/14 ctest green): unauthorized `cmd.exe` reader → correlated in ~400 ms,
`suspend OK`, **sentinel file never written = 0 bytes read**; resume → read
completes (pause, not kill); authorized-signer reader → `authorized`, not
suspended, completes. Residual: on a *hot* file (fresh temp file under Defender
rescan) the authorized path saw a few ~800 ms uncorrelated holds before the
fast-path kicked in — a real flagship file (`~/.ssh/id_rsa`) is not
continuously rescanned, so this is largely a test-environment artifact, but the
"authorized path must be fast" caveat is real under adversarial file churn.

**Still sketch-accurate:** pure usermode (no driver, no PPL, no testsigning);
suspend gated on `set_response_enforcement_windows(1)`; guard on an
unregistered path is armed-but-inert; fail-open on every uncertainty; one
handle per guarded file; can't guard a file a legit owner holds open when the
guard is added (RWH can't be granted — worker retries).

---

## Sequencing

| Order | Workstream | Depends on | Notes |
|---|---|---|---|
| 1 | WS1 actor identity spine | — | Everything else needs it. Includes the `telemetry.h` ABI change. |
| 2 | WS3 catalog signing | (feeds WS1's signer field) | Small; do concurrently with WS1's worker-thread wiring. |
| 3 | WS6 latency reduction | WS1 (drain-thread split) | Small; do early — its measurements gate WS7. |
| 4 | WS2 registry store | telemetry.h settled | Parallel to WS1 tail. |
| 5 | WS4 evaluate helper | WS1 + WS2 | Thin glue. |
| 6 | WS5 response primitives | WS1 (reuse guard) | Disarmed by default. |
| 7 | WS7 oplock hold | WS4 + WS5 + WS6 gate | Only if WS6 says Tier A isn't fast enough, or for a hard flagship claim. |

**Milestone "reactive MVP":** WS1–WS6 done, `evaluate_access_windows` +
`suspend_process_windows` exercised end to end against a real unauthorized
process. WS7 folds in when its gate opens.

## End-to-end test (`test_reactive_e2e.cpp`)

Register a protected file + an owner signer. Run an unauthorized test binary
that opens and reads the file. Assert:
1. `core` emits the file event with the correct `actor_sequence_number`.
2. `evaluate_access_windows` → `UNAUTHORIZED`.
3. `suspend_process_windows` with the event's identity → succeeds; the binary is
   suspended.
4. `terminate_process_windows` → the binary is gone.
5. Same file, an authorized-signer binary → `AUTHORIZED`, no action taken.
6. (WS7) guarded file variant → unauthorized binary suspended with 0 bytes read.

## ABI / boundary notes

- WS1 changes `TelemetryHeader` layout → the current `antitheft-agent` pipe
  consumer breaks until reworked. Flag loudly in the commit; that rework is the
  already-planned "core before Rust" follow-up.
- All new FFI keeps the Phase 5 boundary: `core` stores and matches, the agent
  loads config and pushes entries + makes the response decision. `core` never
  parses `protect-community/configs/antitheft/`.
- `set_response_enforcement_windows` default 0, and
  `initialize_telemetry_engine` must never arm it implicitly (`CLAUDE.md`).

## Honest limitations of the shipped result

- Prevents: multi-step credential theft, persistence installation, clipboard
  swaps, anything slower than the WS6 budget; plus synchronous prevention for
  the WS7 guarded file set.
- Does not prevent: a single fast read of a non-guarded protected file; theft
  from PPL-protected processes; kernel/BYOVD attackers; offline cracking of an
  encrypted blob whose read we observed but did not beat.
- The kernel driver (`WINDOWS_COVERAGE_PLAN.md` Phase 7) is still what turns
  "usually interrupt" into "deny". This milestone is the useful, shippable
  interim.
