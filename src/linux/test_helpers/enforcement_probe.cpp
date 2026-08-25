// Minimal, deliberately-unclassified probe process for test_enforcement_e2e.cpp.
// Not linked against kinnector-core -- it must be a genuinely separate binary
// so its exec-time trust level is whatever the harness configures via
// AddTrustedExecInode/AddSensitiveInode, never inherited from the test
// runner's own (already-exec'd) image. The LSM hooks key off the calling
// task, so fork() alone from the harness would not exercise the same code
// path a real untrusted process takes -- this binary is exec'd into that
// forked child.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <open_read|open_write> <path>\n", argv[0]);
        fprintf(stderr, "       %s sleep <seconds>\n", argv[0]);
        return 2;
    }
    const char* op = argv[1];

    // Phase 5 (LINUX_COVERAGE_PLAN.md): stand-in for a long-lived "owner" process
    // (e.g. a password manager) that test_enforcement_e2e's ptrace/kill tests
    // target from a separate, unrelated process while this one is still alive.
    if (strcmp(op, "sleep") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s sleep <seconds>\n", argv[0]);
            return 2;
        }
        sleep(static_cast<unsigned int>(atoi(argv[2])));
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: %s <open_read|open_write> <path>\n", argv[0]);
        return 2;
    }
    const char* path = argv[2];

    int flags;
    if (strcmp(op, "open_read") == 0) {
        flags = O_RDONLY;
    } else if (strcmp(op, "open_write") == 0) {
        flags = O_WRONLY;
    } else {
        fprintf(stderr, "unknown op: %s\n", op);
        return 2;
    }

    int fd = open(path, flags);
    if (fd < 0) {
        return errno; // caller (test_enforcement_e2e) asserts against the exact errno
    }
    close(fd);
    return 0;
}
