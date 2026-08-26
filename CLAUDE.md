# core - agent instructions

Kernel-level telemetry & enforcement engine (eBPF/BPF LSM, ETW, ESF). See `README.md` for architecture, hook inventory, FFI usage, and performance design - this file is operational guidance for anyone (human or agent) working in the source, not a duplicate of that.

## Platform status (don't take README's "supported" table as historical - it's current, check it)

- **Linux**: full implementation, enforcement-capable (BPF LSM hooks can deny). Reference platform.
- **Windows**: telemetry-only. `src/windows/etw_consumer.cpp` is real (three ETW kernel providers). `src/windows/driver_helper.cpp` is a one-line no-op stub - there is no kernel-driver enforcement layer yet. See `src/windows/WINDOWS_COVERAGE_PLAN.md` for the handoff plan before adding real driver logic.
- **macOS**: no source at all. `src/macos/MACOS_COVERAGE_PLAN.md` is a design doc only. Don't assume ESF/FSEvents code exists anywhere - `CMakeLists.txt` lists macOS sources that don't exist yet, so a Darwin build will fail.

## Safety-critical: kernel-blocking mechanisms

**Never pair a mount-wide fanotify mark (`FAN_MARK_MOUNT`) with a `*_PERM` (blocking) event type.** This has caused a real, unrecoverable machine hang requiring a hard reboot (`FAN_MARK_MOUNT` + `FAN_OPEN_PERM` on `/` blocks every `open()` on the entire filesystem, including anything you'd use to intervene). Mount-wide marks are fine for notify-only events; any blocking/permission fanotify mark must be scoped to a specific path.

**Any function that can arm blocking behavior (fanotify `*_PERM`, a new BPF LSM deny path) must default to off**, and the default init path (`initialize_telemetry_engine`, called by every product and test transitively) must never opt in implicitly.

**Before running any root-level kernel/BPF/fanotify test for the first time, wrap it in `timeout <N>s`, no exceptions.** Reason through blast radius first: what's the broadest thing that could block, and is one thread solely responsible for unblocking it? If yes, scope it down before running - don't test-and-see. This build is `-DNDEBUG`, so `assert()` calls with required side effects are silently elided - never wrap a call that has a required side effect (e.g. `Start()`, spawning a thread) inside `assert()`; assign the result to a variable first, `assert()` the variable.

If everything requiring root suddenly starts failing with `Permission denied` pre-prompt (`sudo`, `su`, `chmod` on unrelated files) after loading BPF LSM hooks, that's very likely leftover pinned LSM links from a prior test run denying execution/chmod system-wide, not an external lockout - check `bprm_creds_for_exec`/`path_chmod` pin state and unpin, reboot only as last resort (bpffs isn't disk-backed, nothing survives reboot).

## BPF verifier gotcha (kinnector.bpf.c)

Null-checking a struct field, then re-reading that *same field expression* into a new variable later, does **not** carry the null-check to the second read - the verifier tracks the specific value produced by one read, not "this expression was checked earlier." Always null-check the exact variable you're about to dereference, at the point you assign it:

```c
// wrong - verifier rejects the second read's pointer arithmetic as unchecked
if (!newsock || !newsock->sk) return 0;
struct sock *sk = newsock->sk;
BPF_CORE_READ(sk, __sk_common.skc_family);

// right
struct sock *sk = newsock->sk;
if (!sk) return 0;
BPF_CORE_READ(sk, __sk_common.skc_family);
```

Only surfaces at real `bpf_object__load()` under a real kernel - never in a normal compile or mock-mode test run.

## kinnector.bpf.c is shared, not Antitheft- or Warden-owned

Both `warden`'s `wardend` (static-links `libkinnector-core.a`) and `antitheft-agent` (dylib-links `libkinnector-core.so`) build from this exact same `kinnector.bpf.c` through one `EbpfLoader` singleton (`src/ffi.cpp`). A `deployment_mode` config value (`MODE_WARDEN`/`MODE_ANTITHEFT`) exists specifically so product-specific logic can be gated without touching the other product's enforcement path. Any change to a shared hook (`file_open`, `file_permission`, `ptrace_access_check`, `task_kill`, etc.):
- gate new product-specific branches behind `deployment_mode`, appended after the other product's existing checks, not interleaved with them
- never reuse a map/config index another product already reads - new state goes in new maps
- run `test_enforcement_e2e` (the only target that issues real syscalls and asserts real errno against protected resources) as a regression gate before merging, not just your own product's functional test

## Known debt

`kinnector.bpf.c`'s `TREE_TRUSTED_ADMIN` execution-restriction check hardcodes an allowlist of admin binary names (`sh`, `bash`, `logrotate`, `apache2ctl`, `pg_ctl`, etc., built char-by-char) directly in the BPF source. The wider workspace's constitution is that classification/match lists load dynamically from `protect-community/configs/warden` via `kinnector-config`, not live hardcoded in source - this hasn't been migrated yet. Don't copy this pattern for new match lists; flag it rather than extend it.

## Build & test

```bash
cmake -B build
cmake --build build --config Release
```

Full test list and root-requiring targets are in `README.md`'s Build section. `test_enforcement_e2e` and `test_lsm` need real root and a BPF-LSM-capable kernel (`bpf` present in `/sys/kernel/security/lsm`) to exercise their real-kernel path - both silently fall back to mock-mode assertions otherwise, which will pass without proving anything. If you're re-verifying enforcement behavior after a kernel-side change, confirm you're actually hitting the real-kernel branch, not the mock fallback.
