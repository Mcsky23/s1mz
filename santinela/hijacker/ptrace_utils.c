#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int poke_text(pid_t pid, void *where, void *new_text, void *old_text, size_t len) {
    if (len % sizeof(void *) != 0) {
        printf("invalid len, not a multiple of %zd\n", sizeof(void *));
        return -1;
    }

    long poke_data;
    for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
        memmove(&poke_data, new_text + copied, sizeof(poke_data));
        if (old_text != NULL) {
            errno = 0;
            long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
            if (peek_data == -1 && errno) {
                perror("PTRACE_PEEKTEXT");
                return -1;
            }
        memmove(old_text + copied, &peek_data, sizeof(peek_data));
        }
        if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
            perror("PTRACE_POKETEXT");
        return -1;
        }
    }
    return 0;
}


int do_wait(const char *name) {
    int status;
    if (wait(&status) == -1) {
        perror("wait");
        return -1;
    }
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) == SIGTRAP) {
            return 0;
        }
        printf("%s unexpectedly got status %s\n", name, strsignal(status));
        return -1;
    }
    printf("%s got unexpected status %d\n", name, status);
    return -1;

}

int singlestep(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
        perror("PTRACE_SINGLESTEP");
        return -1;
    }
    return do_wait("PTRACE_SINGLESTEP");
}


void check_yama(void) {
    FILE *yama_file = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (yama_file == NULL) {
        return;
    }
    char yama_buf[8];
    memset(yama_buf, 0, sizeof(yama_buf));
    fread(yama_buf, 1, sizeof(yama_buf), yama_file);
    if (strcmp(yama_buf, "0\n") != 0) {
        printf("\nThe likely cause of this failure is that your system has "
               "kernel.yama.ptrace_scope = %s",
               yama_buf);
        printf("If you would like to disable Yama, you can run: "
             "sudo sysctl kernel.yama.ptrace_scope=0\n");
    }
    fclose(yama_file);
}



int detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
        perror("PTRACE_DETACH");
        check_yama();
        return -1;
    }
}

int attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
        perror("PTRACE_ATTACH");
        check_yama();
        return -1;
    }
    return 0;
}

int getregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
        perror("PTRACE_GETREGS");
        detach(pid);
        return -1;
    } 
}

int setregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
        perror("PTRACE_SETREGS");
        detach(pid);
        return -1;
    }
}

int cont(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
        perror("PTRACE_CONT");
        detach(pid);
        return -1;
    }
    if (do_wait("PTRACE_CONT")) {
        detach(pid);
        return -1;
    }
}
