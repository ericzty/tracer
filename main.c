#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>

int do_child(int argc, char **argv);
int do_trace(pid_t child);

#define SECCOMP_FLAG SECCOMP_FILTER_FLAG_SPEC_ALLOW

int install_filter(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        // only trace getpid
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 39, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        exit(EXIT_FAILURE);
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FLAG, &prog)) {
        perror("seccomp");
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s prog args\n", argv[0]);
        exit(1);
    }

    pid_t child = fork();
    if (child == 0) {
        return do_child(argc-1, argv+1);
    } else {
        return do_trace(child);
    }
}

int do_child(int argc, char **argv) {
    char *args [argc+1];
    int child;

    memcpy(args, argv, argc * sizeof(char*));
    args[argc] = NULL;
    
    child = getpid();

    install_filter();
    kill(child, SIGSTOP);
    return execvp(args[0], args);
}

int wait_for_syscall(pid_t child);

int do_trace(pid_t child) {
    int status, syscall, retval;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {
        if (wait_for_syscall(child) != 0) break;

        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        //       fprintf(stderr, "syscall(%d) = ", syscall);

        if (wait_for_syscall(child) != 0) break;

        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        //        fprintf(stderr, "%d\n", retval);
    }
    return 0;
}

int wait_for_syscall(pid_t child) {
    int status;

    int options = 0;
    options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK;  // Follow forks
    options |= PTRACE_O_TRACEEXEC;     // Handle execs more reliably
    options |= PTRACE_O_TRACESYSGOOD;  // When stepping through syscalls, be clear
    options |= PTRACE_O_TRACESECCOMP;  // Actually receive the syscall stops we requested
    options |= PTRACE_O_EXITKILL;      // Kill tracees on exit

    if (ptrace(PTRACE_SEIZE, child, NULL, options) < 0) {
        perror("cant seize");
    }

    waitpid(child, &status, 0);
    printf("%d", status);
    while (WIFSTOPPED(status) && (status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
        if (ptrace(PTRACE_CONT, child, NULL, 0) < 0) {
            perror("Failed to resume child: ");
        }
        waitpid(child, &status, 0);
        printf("%d", status);
    }
    return 1;

    /*
    while (1) {
        printf("c");
        struct ptrace_syscall_info info;
        waitpid(child, &status, 0);
           if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
           return 0;
           if (WIFEXITED(status))
           return 1;
        long rc = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(info), &info);
        if (rc < 0) {
            perror("a");
        } else {
            printf("b");
        }
    }
    */
}

