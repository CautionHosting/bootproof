/* Minimal ptrace syscall tracer: logs open/openat paths, read/write on fds
 * >= 3, dup, fcntl. Usage: trace <cmd> [args...] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <elf.h>
#include <errno.h>

static const char *sysname(long n) {
    switch (n) {
    case 0: return "read";
    case 1: return "write";
    case 2: return "open";
    case 14: return "fcntl";
    case 21: return "dup";
    case 22: return "dup2";
    case 56: return "clone";
    case 334: return "execve";
    case 302: return "openat";
    default: return NULL;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: trace cmd [args...]\n"); return 2; }
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(127);
    }
    int status;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0,
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    int in_syscall = 0;
    long entry_args[6];
    int child_exited = 0;
    while (!child_exited) {
        pid_t p = waitpid(-1, &status, 0);
        if (p < 0) break;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (p == child) child_exited = 1;
            continue;
        }
        int sig = WSTOPSIG(status);
        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            ptrace(PTRACE_GETREGS, p, 0, &r);
            long n = (long)r.orig_rax;
            if (!in_syscall) {
                in_syscall = 1;
                entry_args[0] = (long)r.rdi;
                entry_args[1] = (long)r.rsi;
                entry_args[2] = (long)r.rdx;
            } else {
                in_syscall = 0;
                long ret = (long)r.rax;
                const char *name = sysname(n);
                if (name && (n == 2 || n == 302)) {
                    char path[2048];
                    const char *src = (n == 302) ? (const char *)entry_args[1] : (const char *)entry_args[0];
                    size_t len = 0;
                    while (len < sizeof(path) - 1) {
                        long v = ptrace(PTRACE_PEEKDATA, p, (void *)(src + len), NULL);
                        memcpy(path + len, &v, 4);
                        if (memchr(&v, 0, 4)) break;
                        len += 4;
                    }
                    path[len] = 0;
                    fprintf(stderr, "T%d %s(\"%s\") = %ld\n", (int)p, name, path, ret);
                } else if (name && (n == 0 || n == 1) && entry_args[0] >= 3) {
                    fprintf(stderr, "T%d %s(fd=%ld) = %ld\n", (int)p, name, entry_args[0], ret);
                } else if (name && (n == 21 || n == 22)) {
                    fprintf(stderr, "T%d %s(%ld) = %ld\n", (int)p, name, entry_args[0], ret);
                } else if (name && n == 14) {
                    fprintf(stderr, "T%d fcntl(fd=%ld, cmd=%ld) = %ld\n", (int)p, entry_args[0], entry_args[1], ret);
                }
            }
            ptrace(PTRACE_SYSCALL, p, 0, 0);
        } else if (sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, p, 0, 0);
        } else if (sig) {
            ptrace(PTRACE_SYSCALL, p, 0, (void *)(long)sig);
        } else {
            ptrace(PTRACE_SYSCALL, p, 0, 0);
        }
    }
    return 0;
}
