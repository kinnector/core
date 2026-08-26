// LINUX_COVERAGE_PLAN.md, "Testing strategy" item 1: the one thing every
// existing ctest target in this suite does NOT do is issue a real syscall
// from a distinct unprivileged process against a protected resource and
// check the kernel actually returned -EACCES. This target does that. It is
// the regression base Phase 2 (PID-reuse), Phase 3 (owner-allowlist), and
// Phase 4 (config-driven install-binary detection) each extend with new
// cases below; Phase 5 (ptrace/kill) still needs one, once
// protected_owner_pids exists -- see the plan doc.
//
// Deliberately NOT graceful about missing BPF LSM support (unlike
// test_ebpf_loader.cpp's TestRealKernelMode, which skips quietly when
// IsMockMode()/!IsLsmActive()): this is the only target asserting actual
// kernel-level deny behavior, so silently no-op'ing here would defeat the
// point exactly the way the "Testing strategy" section calls out. Run as
// root on a kernel with "bpf" in /sys/kernel/security/lsm.
//
// Base scope: file_open's sensitive-inode read deny and file_permission's
// protected-static-inode write deny -- the two mechanisms Phase 1 activates
// telemetry/propagation around and the ones the plan's "bottom line" calls
// the core gap. ptrace_access_check/task_kill owner-process protection is
// left for Phase 5, once protected_owner_pids exists -- see the plan doc.
#include "ebpf_loader.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <signal.h>

using namespace kinnector::lnx;

namespace {

constexpr uint32_t kConfigBlockingEnabled = 0; // kinnector.bpf.c: CONFIG_BLOCKING_ENABLED
constexpr uint32_t kConfigDeploymentMode = 5;  // kinnector.bpf.c: CONFIG_DEPLOYMENT_MODE
constexpr uint32_t kModeWarden = 1;            // kinnector.bpf.c: MODE_WARDEN
constexpr uint32_t kModeAntitheft = 2;         // kinnector.bpf.c: MODE_ANTITHEFT

// Must match kinnector.bpf.c's resource_owner_hash() / ebpf_loader.cpp's
// ResourceOwnerHash() exactly -- used here only to pick a "definitely not the
// probe" fake owner inode that provably hashes to a different 64-slot bucket,
// so the deny tests below can't flake on an accidental hash collision.
uint32_t ResourceOwnerHash(uint64_t exec_ino) {
    return static_cast<uint32_t>((exec_ino * 2654435761ULL) & 0x3FULL);
}

// Safety net for the sudo/su/pkexec lockout in linux_coverage_plan_phasing
// memory: this test runs as root with blocking_enabled=1 against real system
// paths (kWardenPinnedLinkPaths), and EbpfLoader::Stop() deliberately leaves
// those pins alive (correct for production, catastrophic for a test that
// crashes mid-run without reaching its own cleanup). unlink() is
// async-signal-safe, so a crash still drops every pin's last reference before
// the process dies -- do NOT call bpf_link__destroy()/anything from libbpf
// here, it is not guaranteed signal-safe.
extern "C" void ForceUnpinOnCrash(int sig) {
    for (size_t i = 0; i < kinnector::lnx::kWardenPinnedLinkPathsCount; ++i) {
        unlink(kinnector::lnx::kWardenPinnedLinkPaths[i]);
    }
    _exit(128 + sig);
}

void InstallCrashUnpinHandler() {
    struct sigaction sa{};
    sa.sa_handler = ForceUnpinOnCrash;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for (int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTERM, SIGINT}) {
        sigaction(sig, &sa, nullptr);
    }
}

const char* ProbePath() {
    // Built alongside this test into build/bin by CMakeLists.txt; ctest's
    // working directory for this target is build/ (verified empirically --
    // add_test() default WORKING_DIRECTORY is the top build dir here).
    return "bin/kinnector-enforcement-probe";
}

// Runs the probe as a genuinely separate process via fork+exec (see
// enforcement_probe.cpp's header comment for why fork() alone isn't enough).
// Returns the probe's exit code: 0 on successful open(), or the errno the
// open() failed with, or -1 if the harness itself couldn't run the probe.
int RunProbe(const char* op, const std::string& path) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl(ProbePath(), ProbePath(), op, path.c_str(), (char*)nullptr);
        _exit(127); // exec itself failed -- distinguishable from any real errno
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  probe did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// Phase 5 (LINUX_COVERAGE_PLAN.md): forks+execs the probe in "sleep <seconds>"
// mode and returns immediately without waiting, so the caller can attempt
// ptrace/kill against it from a third, unrelated process while it's still
// alive. Caller is responsible for eventually reaping it (it exits on its own
// once the sleep elapses, or immediately if a kill attempt against it succeeds).
pid_t StartProbeSleeping(const char* probe_path, int seconds) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (sleeper)");
        return -1;
    }
    if (pid == 0) {
        execl(probe_path, probe_path, "sleep", std::to_string(seconds).c_str(), (char*)nullptr);
        _exit(127);
    }
    return pid;
}

// Attempts ptrace(PTRACE_ATTACH) against `target` from a genuinely separate,
// unrelated process (never itself exec'd a protected_owner_binaries entry).
// Returns 0 on success (in which case it also detaches before exiting, so the
// target keeps running regardless of whether the LSM should have denied this),
// or the errno ptrace() failed with.
int AttackerPtraceAttach(pid_t target) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (ptrace attacker)");
        return -1;
    }
    if (pid == 0) {
        if (ptrace(PTRACE_ATTACH, target, nullptr, nullptr) != 0) {
            _exit(errno);
        }
        // Attach unexpectedly succeeded -- release the target immediately so
        // it isn't left stopped regardless of what this test asserts.
        waitpid(target, nullptr, 0); // reap the SIGSTOP PTRACE_ATTACH generates
        ptrace(PTRACE_DETACH, target, nullptr, nullptr);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid (ptrace attacker)");
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Attempts kill(target, sig) from a genuinely separate, unrelated process.
// Returns 0 on success or the errno kill() failed with.
int AttackerKill(pid_t target, int sig) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (kill attacker)");
        return -1;
    }
    if (pid == 0) {
        _exit(kill(target, sig) == 0 ? 0 : errno);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid (kill attacker)");
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Runs the probe as PID 1 of a brand-new, throwaway PID namespace: forks an
// intermediate process that calls unshare(CLONE_NEWPID) (which only affects
// that process's *future* children, not itself) and then forks again --
// the grandchild is born as PID 1 of the fresh namespace and exec's the
// probe there. bpf_get_current_pid_tgid() resolves relative to the calling
// task's own active PID namespace, so the grandchild is observed by the LSM
// hooks as pid=1 regardless of its real (outer-namespace) PID -- this is
// what makes pid_tree_type_map's PID-reuse bug (Phase 2) deterministically
// reproducible without waiting on real host-wide PID wraparound. Requires
// CAP_SYS_ADMIN (already guaranteed: the whole binary requires root).
int RunProbeInFreshPidNs(const char* probe_path, const char* op, const std::string& path) {
    pid_t mid = fork();
    if (mid < 0) {
        perror("fork (intermediate)");
        return -1;
    }
    if (mid == 0) {
        if (unshare(CLONE_NEWPID) != 0) {
            perror("unshare(CLONE_NEWPID)");
            _exit(126);
        }
        pid_t inner = fork();
        if (inner < 0) {
            perror("fork (inner, pid 1 of new ns)");
            _exit(126);
        }
        if (inner == 0) {
            execl(probe_path, probe_path, op, path.c_str(), (char*)nullptr);
            _exit(127);
        }
        int inner_status = 0;
        if (waitpid(inner, &inner_status, 0) < 0) {
            perror("waitpid (inner)");
            _exit(126);
        }
        _exit(WIFEXITED(inner_status) ? WEXITSTATUS(inner_status) : 125);
    }
    int status = 0;
    if (waitpid(mid, &status, 0) < 0) {
        perror("waitpid (intermediate)");
        return -1;
    }
    if (!WIFEXITED(status)) {
        std::cerr << "  intermediate process did not exit normally (status=" << status << ")" << std::endl;
        return -1;
    }
    return WEXITSTATUS(status);
}

// Byte-for-byte copy of the probe binary at a fresh path, so it gets a
// distinct inode from ProbePath()'s -- used only by the Phase 2 PID-reuse
// regression test, which needs a second "generically verified, but never
// itself an install binary" exec target that isn't the same inode as the one
// TestInstallBinaryMapConfigDrivenDetection registers in install_binary_map.
bool CopyProbeBinary(std::string& path_out, uint64_t& inode_out) {
    char tmpl[] = "/tmp/kinnector_e2e_probe_copy_XXXXXX";
    int out_fd = mkstemp(tmpl);
    if (out_fd < 0) {
        perror("mkstemp (probe copy)");
        return false;
    }
    int in_fd = open(ProbePath(), O_RDONLY);
    if (in_fd < 0) {
        perror("open (probe source)");
        close(out_fd);
        unlink(tmpl);
        return false;
    }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        if (write(out_fd, buf, static_cast<size_t>(n)) != n) {
            ok = false;
            break;
        }
    }
    if (n < 0) ok = false;
    close(in_fd);
    close(out_fd);
    if (!ok || chmod(tmpl, 0755) != 0) {
        unlink(tmpl);
        return false;
    }
    struct stat st{};
    if (stat(tmpl, &st) != 0) {
        unlink(tmpl);
        return false;
    }
    path_out = tmpl;
    inode_out = st.st_ino;
    return true;
}

// Phase 6 (LINUX_COVERAGE_PLAN.md): also returns st_dev, since every map this
// harness registers resources in now takes the canonical (dev, ino) identity.
bool MakeTempFile(std::string& path_out, uint64_t& inode_out, uint64_t& dev_out) {
    char tmpl[] = "/tmp/kinnector_e2e_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        perror("mkstemp");
        return false;
    }
    if (write(fd, "protected", 9) != 9) {
        close(fd);
        unlink(tmpl);
        return false;
    }
    close(fd);
    struct stat st{};
    if (stat(tmpl, &st) != 0) {
        unlink(tmpl);
        return false;
    }
    path_out = tmpl;
    inode_out = st.st_ino;
    dev_out = st.st_dev;
    return true;
}

int g_failures = 0;

// EbpfLoader has no removal API for sensitive_inodes_map/resource_owner_map
// (Add-only -- see AddSensitiveInode/AddResourceOwner), and every test below
// registers its temp file's (dev, ino) into one of those maps before
// unlink()ing it. Freeing the inode immediately let the filesystem recycle
// that exact inode number for a LATER test's fresh MakeTempFile() call within
// the same run, which then collided with the earlier, still-live-in-the-map
// registration -- causing spurious EACCES on completely unrelated files
// (including this harness's own mkstemp() calls). Deferring every cleanup to
// process exit keeps every inode this run has ever used alive (never freed,
// never recyclable) for the run's whole lifetime, eliminating the collision
// outright rather than just making it less likely.
std::vector<std::string> g_deferred_unlinks;
void DeferUnlink(const std::string& path) { g_deferred_unlinks.push_back(path); }
void RunDeferredUnlinks() {
    for (const auto& p : g_deferred_unlinks) unlink(p.c_str());
    g_deferred_unlinks.clear();
}

void Check(bool cond, const std::string& msg) {
    if (cond) {
        std::cout << "  - PASS: " << msg << std::endl;
    } else {
        std::cerr << "  - FAIL: " << msg << std::endl;
        g_failures++;
    }
}

// file_open's sensitive-inode deny (kinnector.bpf.c ~:1032-1056) only fires
// when the accessing process's process_threshold_map entry is exactly 1
// (freshly-exec'd, unclassified -- the default any untrusted binary gets
// once blocking_enabled=1, per bprm_creds_for_exec's `else if
// (blocking_enabled) { threshold = 1; }` branch). The probe binary is never
// added to trusted_exec_inodes ahead of this test, so it gets that default.
void TestSensitiveInodeReadDeny(EbpfLoader& loader) {
    std::cout << "[e2e] sensitive-inode read: unclassified process denied at open()..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == EACCES, "open() denied with EACCES (got " + std::to_string(rc) + ")");
}

// file_permission's protected-static-inode deny (kinnector.bpf.c
// ~:1114-1124) fires for ANY nonzero threshold, not just ==1 -- run this
// before TestSensitiveInodeReadAllow below, which permanently registers the
// probe binary's exec inode with a nonzero (but non-1) trust level for the
// remainder of this process's lifetime and would otherwise make this test's
// "denied" assertion depend on run order instead of standing on its own.
void TestProtectedStaticInodeWriteDeny(EbpfLoader& loader) {
    std::cout << "[e2e] protected-static-inode write: unclassified process denied at open() for write..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddProtectedStaticInode(dev, ino)) { Check(false, "AddProtectedStaticInode failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_write", path);
    DeferUnlink(path);
    Check(rc == EACCES, "write-open denied with EACCES (got " + std::to_string(rc) + ")");
}

// Control case: proves the deny above isn't unconditional / a
// misconfigured always-block. bprm_creds_for_exec stores whatever nonzero
// value trusted_exec_inodes has for the exec'd binary as that process's
// threshold (kinnector.bpf.c ~:1663-1669); file_open's sensitive-inode
// check specifically tests `threshold == 1`, so a role-classified process
// (threshold=2, standing in for e.g. ROLE_DATABASE) takes the allow path
// even though it's still "nonzero". Run this last -- see the comment on
// TestProtectedStaticInodeWriteDeny above for why.
void TestSensitiveInodeReadAllowForClassifiedProcess(EbpfLoader& loader) {
    std::cout << "[e2e] sensitive-inode read: role-classified (threshold=2) process allowed at open() (control case)..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }

    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) { Check(false, "could not stat probe binary"); unlink(path.c_str()); return; }
    if (!loader.AddTrustedExecInode(probe_st.st_ino, /*trust_level=*/2)) {
        Check(false, "AddTrustedExecInode failed");
        unlink(path.c_str());
        return;
    }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == 0, "open() succeeded (got " + std::to_string(rc) + ")");
}

// Phase 3 (LINUX_COVERAGE_PLAN.md): resource_owner_map must be entirely inert
// for a MODE_WARDEN (or unset-mode) deployment -- this is the regression test
// for the "Critical constraint" gating requirement, not just Phase 3's own
// mechanism. The resource here has an owner list that would deny the probe if
// consulted; if this test passes it proves resource_owner_map genuinely isn't
// being read outside MODE_ANTITHEFT, not just that it happens to allow this case.
void TestResourceOwnerMapIgnoredInWardenMode(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource_owner_map ignored under MODE_WARDEN (regression for the mode gate)..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeWarden)) {
        Check(false, "SetConfigValue(MODE_WARDEN) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    uint64_t fake_owner = probe_ino + 1;
    while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
    if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); unlink(path.c_str()); return; }

    // Probe is not in the owner list -- if resource_owner_map were consulted,
    // this would be denied. It must succeed under MODE_WARDEN regardless.
    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == 0, "open() succeeded under MODE_WARDEN despite a denying owner list (got " + std::to_string(rc) + ")");
}

// Phase 3's load-bearing case: a third, unrelated (but otherwise generically
// trusted -- threshold=2, set by TestSensitiveInodeReadAllowForClassifiedProcess
// above) process is refused before the read completes because it isn't a
// configured owner of this specific resource, even though generic trust alone
// would have let it through the pre-existing threshold check.
void TestResourceOwnerAllowlistDenyUnrelatedProcess(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource owner-allowlist: unrelated process denied at open() under MODE_ANTITHEFT..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    uint64_t fake_owner = probe_ino + 1;
    while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
    if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == EACCES, "open() denied with EACCES for a non-owner (got " + std::to_string(rc) + ")");
}

// Control case: the same resource, but with the probe's own exec inode added
// as one of (multiple) configured owners -- proves the deny above isn't
// unconditional and that resource_owner_map's bitmask correctly ORs more than
// one owner in without losing either.
void TestResourceOwnerAllowlistAllowConfiguredOwner(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource owner-allowlist: configured owner allowed at open() (control case)..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }
    uint64_t other_owner = probe_ino + 1;
    while (ResourceOwnerHash(other_owner) == ResourceOwnerHash(probe_ino)) other_owner++;
    if (!loader.AddResourceOwner(dev, ino, other_owner)) { Check(false, "AddResourceOwner(other_owner) failed"); unlink(path.c_str()); return; }
    if (!loader.AddResourceOwner(dev, ino, probe_ino)) { Check(false, "AddResourceOwner(probe_ino) failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == 0, "open() succeeded for a configured owner (got " + std::to_string(rc) + ")");
}

// file_permission's owner check is independent of protected_static_inodes/
// sensitive_inodes_map -- exercise it directly on a resource that is neither.
void TestResourceOwnerAllowlistWriteDeny(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] resource owner-allowlist: unrelated process denied at open() for write..." << std::endl;
    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    uint64_t fake_owner = probe_ino + 1;
    while (ResourceOwnerHash(fake_owner) == ResourceOwnerHash(probe_ino)) fake_owner++;
    if (!loader.AddResourceOwner(dev, ino, fake_owner)) { Check(false, "AddResourceOwner failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_write", path);
    DeferUnlink(path);
    Check(rc == EACCES, "write-open denied with EACCES for a non-owner (got " + std::to_string(rc) + ")");
}

// Phase 4 (LINUX_COVERAGE_PLAN.md): "add a new package-manager binary via config
// only, confirm it's recognized as an install-context root without a kernel-object
// rebuild." The probe binary's name/path matches none of the old hardcoded
// is_install_binary() substrings (npm/yarn/pip/...), so under the pre-Phase-4 code
// this scenario was structurally impossible without editing kinnector.bpf.c and
// rebuilding. Signal used: bprm_creds_for_exec's install_binary_map hit sets
// TREE_INSTALL_CONTEXT, and file_open's sensitive-file deny is `threshold==1 OR
// is_install_session()` -- so even though probe is independently classified
// threshold=2 ("verified", proven to bypass this same deny on its own by
// TestSensitiveInodeReadAllowForClassifiedProcess above), registering it in
// install_binary_map via UpdateMapEntry alone (no .bpf.c change) must still
// deny it here through the is_install_session() branch specifically.
void TestInstallBinaryMapConfigDrivenDetection(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] install_binary_map: config-only registration recognized as install-context root..." << std::endl;
    if (!loader.UpdateMapEntry(BpfMapType::InstallBinaryMap, /*pid unused*/0, probe_ino, 1)) {
        Check(false, "UpdateMapEntry(InstallBinaryMap) failed");
        return;
    }

    std::string path;
    uint64_t ino, dev;
    if (!MakeTempFile(path, ino, dev)) { Check(false, "could not create temp resource"); return; }
    if (!loader.AddSensitiveInode(dev, ino, /*category=*/1)) { Check(false, "AddSensitiveInode failed"); unlink(path.c_str()); return; }

    int rc = RunProbe("open_read", path);
    DeferUnlink(path);
    Check(rc == EACCES, "open() denied with EACCES via config-only install-context marking (got " + std::to_string(rc) + ")");
}

// Phase 2 (LINUX_COVERAGE_PLAN.md), testing strategy item 2: the direct
// regression test for the bug the phase fixes. G1 execs the install_binary_map-
// registered probe (correctly self-marking TREE_INSTALL_CONTEXT) as PID 1 of a
// fresh PID namespace, then exits. G2 -- an unrelated process with its own
// distinct start_time, exec'ing a *copy* of the probe that is independently
// classified threshold=2 but NOT itself install-binary-registered -- is also
// observed as PID 1 of its own fresh namespace. With the pre-Phase-2 raw-pid
// key, G2 would incorrectly find G1's stale entry at key=1 and inherit
// TREE_INSTALL_CONTEXT, getting denied by file_open's `... OR
// is_install_session()` clause despite being independently verified and not
// itself an install binary. With the (pid, start_time) key, G2's lookup misses
// (different start_time), so it isn't wrongly denied.
void TestPidReuseInstallContextNotInherited(EbpfLoader& loader) {
    std::cout << "[e2e] pid_tree_type_map: PID-reuse does not leak install-context across processes..." << std::endl;

    // G1: plant TREE_INSTALL_CONTEXT at (ns-relative pid=1, G1's start_time) by
    // actually exec'ing the install-binary-registered probe. Target file is a
    // plain unregistered temp file -- only the exec-time marking matters here.
    std::string decoy_path;
    uint64_t decoy_ino, decoy_dev;
    if (!MakeTempFile(decoy_path, decoy_ino, decoy_dev)) { Check(false, "could not create decoy resource for G1"); return; }
    int g1_rc = RunProbeInFreshPidNs(ProbePath(), "open_read", decoy_path);
    DeferUnlink(decoy_path);
    if (g1_rc != 0) {
        // probe_ino is already threshold=2 (verified) by this point in the
        // suite and the decoy file isn't sensitive, so G1's own open() should
        // succeed independent of the install-context marking under test.
        Check(false, "G1 (install-context planter) did not exit cleanly (got " + std::to_string(g1_rc) + ")");
        return;
    }

    // G2: a genuinely different exec target (distinct inode, so it can never
    // hit install_binary_map on its own merits), independently verified.
    std::string probe_copy_path;
    uint64_t probe_copy_ino;
    if (!CopyProbeBinary(probe_copy_path, probe_copy_ino)) { Check(false, "could not create probe copy for G2"); return; }
    if (!loader.AddTrustedExecInode(probe_copy_ino, /*trust_level=*/2)) {
        Check(false, "AddTrustedExecInode(probe copy) failed");
        unlink(probe_copy_path.c_str());
        return;
    }

    std::string target_path;
    uint64_t target_ino, target_dev;
    if (!MakeTempFile(target_path, target_ino, target_dev)) {
        Check(false, "could not create target resource for G2");
        unlink(probe_copy_path.c_str());
        return;
    }
    if (!loader.AddSensitiveInode(target_dev, target_ino, /*category=*/1)) {
        Check(false, "AddSensitiveInode(target) failed");
        unlink(probe_copy_path.c_str());
        unlink(target_path.c_str());
        return;
    }

    int g2_rc = RunProbeInFreshPidNs(probe_copy_path.c_str(), "open_read", target_path);
    DeferUnlink(probe_copy_path);
    DeferUnlink(target_path);
    Check(g2_rc == 0, "G2 (unrelated, also observed as pid=1) not denied by G1's install-context marker (got " + std::to_string(g2_rc) + ")");
}

// Phase 5 (LINUX_COVERAGE_PLAN.md): the load-bearing case -- a configured owner
// process (stand-in: the probe binary, registered in protected_owner_binaries)
// must be denied ptrace_attach and SIGKILL from an unrelated, unprivileged
// process under MODE_ANTITHEFT.
void TestProtectedOwnerPtraceKillDeniedUnderAntitheft(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] protected_owner_pids: unrelated process denied ptrace/SIGKILL under MODE_ANTITHEFT..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeAntitheft)) {
        Check(false, "SetConfigValue(MODE_ANTITHEFT) failed");
        return;
    }
    if (!loader.UpdateMapEntry(BpfMapType::ProtectedOwnerBinaries, /*pid unused*/0, probe_ino, 1)) {
        Check(false, "UpdateMapEntry(ProtectedOwnerBinaries) failed");
        return;
    }

    pid_t owner_pid = StartProbeSleeping(ProbePath(), /*seconds=*/2);
    if (owner_pid <= 0) { Check(false, "could not start owner (sleeper) process"); return; }
    usleep(200000); // let bprm_creds_for_exec's Phase 5 stamp land before attacking

    int ptrace_rc = AttackerPtraceAttach(owner_pid);
    Check(ptrace_rc == EACCES, "ptrace_attach denied with EACCES (got " + std::to_string(ptrace_rc) + ")");

    int kill_rc = AttackerKill(owner_pid, SIGKILL);
    Check(kill_rc == EPERM, "SIGKILL denied with EPERM (got " + std::to_string(kill_rc) + ")");

    // Neither attack should have succeeded -- the owner process is still alive
    // and will exit on its own once its sleep elapses.
    waitpid(owner_pid, nullptr, 0);
}

// Regression baseline for the case above / MODE_WARDEN pass-through: with the
// same protected_owner_binaries registration in place, a *new* owner process
// exec'd under MODE_WARDEN must never get stamped into protected_owner_pids in
// the first place (bprm_creds_for_exec's Phase 5 stamping is itself gated
// is_antitheft_mode()) -- so the identical attack that was denied above must
// succeed here, proving Warden's task_kill/ptrace_access_check behavior for a
// process that merely happens to match protected_owner_binaries is unchanged.
void TestProtectedOwnerKillAllowedUnderWarden(EbpfLoader& loader, uint64_t probe_ino) {
    std::cout << "[e2e] protected_owner_pids: SIGKILL allowed under MODE_WARDEN (regression baseline)..." << std::endl;
    if (!loader.SetConfigValue(kConfigDeploymentMode, kModeWarden)) {
        Check(false, "SetConfigValue(MODE_WARDEN) failed");
        return;
    }

    pid_t owner_pid = StartProbeSleeping(ProbePath(), /*seconds=*/5);
    if (owner_pid <= 0) { Check(false, "could not start owner (sleeper) process"); return; }
    usleep(200000);

    int kill_rc = AttackerKill(owner_pid, SIGKILL);
    Check(kill_rc == 0, "SIGKILL succeeded under MODE_WARDEN despite protected_owner_binaries registration (got " + std::to_string(kill_rc) + ")");
    waitpid(owner_pid, nullptr, 0); // reap -- exits immediately once SIGKILL lands
}

} // namespace

int main() {
    if (getuid() != 0) {
        std::cerr << "test_enforcement_e2e must run as root (needs BPF map writes + config_map blocking_enabled)." << std::endl;
        return 1;
    }

    EbpfLoader loader;
    if (!loader.Initialize("kinnector.bpf.o", false)) {
        std::cerr << "Failed to initialize EbpfLoader" << std::endl;
        return 1;
    }
    if (!loader.Start()) {
        std::cerr << "Failed to start EbpfLoader" << std::endl;
        return 1;
    }

    // From here on, real LSM links may get pinned system-wide with this
    // process's test-fixture policy state -- install the crash-safety net
    // before doing anything else that could deny exec() to the whole machine.
    InstallCrashUnpinHandler();

    // Normal (non-crash) shutdown: unlike production Stop() (which
    // deliberately leaves pins alive for hot-reload), this test must fully
    // detach everything it attached before exiting -- see ForceUnpinAllLinks()
    // doc comment and linux_coverage_plan_phasing memory for why.
    auto SafeShutdown = [&]() {
        loader.SetConfigValue(kConfigBlockingEnabled, 0);
        loader.ForceUnpinAllLinks();
        loader.Stop();
    };

    if (loader.IsMockMode() || !loader.IsLsmActive()) {
        std::cerr << "test_enforcement_e2e requires real BPF LSM enforcement -- the kernel must list "
                     "\"bpf\" in /sys/kernel/security/lsm (a boot-cmdline lsm= setting, not something "
                     "this test or a reboot-less privilege change can turn on). Mock/fallback tracepoint "
                     "mode cannot satisfy it: this is the one target in the suite meant to assert actual "
                     "kernel-level deny behavior, so it fails loudly here rather than skipping quietly."
                  << std::endl;
        SafeShutdown();
        return 1;
    }

    if (!loader.SetConfigValue(kConfigBlockingEnabled, 1)) {
        std::cerr << "Failed to enable blocking_enabled" << std::endl;
        SafeShutdown();
        return 1;
    }

    TestSensitiveInodeReadDeny(loader);
    TestProtectedStaticInodeWriteDeny(loader);
    TestSensitiveInodeReadAllowForClassifiedProcess(loader);

    // Phase 3 (LINUX_COVERAGE_PLAN.md): owner-allowlist tests. Must run after
    // TestSensitiveInodeReadAllowForClassifiedProcess -- they depend on the
    // probe binary already being classified threshold=2 by that test, so its
    // open() attempts reach the owner-allowlist branch instead of being
    // denied earlier by the generic threshold==1 check. See that test's own
    // comment for why probe classification can't be moved earlier either.
    struct stat probe_st{};
    if (stat(ProbePath(), &probe_st) != 0) {
        Check(false, "could not stat probe binary for owner-allowlist tests");
    } else {
        uint64_t probe_ino = probe_st.st_ino;
        TestResourceOwnerMapIgnoredInWardenMode(loader, probe_ino);
        TestResourceOwnerAllowlistDenyUnrelatedProcess(loader, probe_ino);
        TestResourceOwnerAllowlistAllowConfiguredOwner(loader, probe_ino);
        TestResourceOwnerAllowlistWriteDeny(loader, probe_ino);

        // Phase 4: also depends on probe already being threshold=2 (see comment
        // on TestInstallBinaryMapConfigDrivenDetection). Registers probe_ino in
        // install_binary_map permanently for the rest of this process.
        TestInstallBinaryMapConfigDrivenDetection(loader, probe_ino);

        // Phase 2: depends on probe_ino already being both threshold=2 and
        // install_binary_map-registered by the two tests above.
        TestPidReuseInstallContextNotInherited(loader);

        // Phase 5: independent of the threshold/install-context state above,
        // but TestProtectedOwnerKillAllowedUnderWarden leaves deployment_mode
        // on MODE_WARDEN, so keep both of these last.
        TestProtectedOwnerPtraceKillDeniedUnderAntitheft(loader, probe_ino);
        TestProtectedOwnerKillAllowedUnderWarden(loader, probe_ino);
    }

    RunDeferredUnlinks();
    SafeShutdown();

    if (g_failures > 0) {
        std::cerr << "\n>>> ENFORCEMENT E2E TEST FAILED (" << g_failures << " check(s)) <<<\n";
        return 1;
    }
    std::cout << "\n>>> ENFORCEMENT E2E TEST PASSED <<<\n";
    return 0;
}
