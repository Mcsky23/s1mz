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
#include "ptrace_utils.c"
#include "../utils/utils.c"

#define STACK_SIZE 0x100

int inject(pid_t pid, char *shellcode, int shellcode_len) {
    // attach to the process
    attach(pid);

    // wait for the process to actually stop
    if (waitpid(pid, 0, WSTOPPED) == -1) {
        perror("wait");
        return -1;
    }

    // save the register state of the remote process
    struct user_regs_struct oldregs;
    getregs(pid, &oldregs);

    void *rip = (void *)oldregs.rip;
    void *rsp = (void *)oldregs.rsp;
    void *rbp = (void *)oldregs.rbp;

    // log_info("their %%rsp           %p\n", rsp);
    // log_info("their %%rbp           %p\n", rbp);
    // log_info("their %%rip           %p\n", rip);

    // allocate memory for shellcode
    struct user_regs_struct newregs;
    memmove(&newregs, &oldregs, sizeof(newregs));
    newregs.rax = 9;                           // mmap
    newregs.rdi = 0;                           // addr
    newregs.rsi = MMAP_SZ;                   // length
    newregs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;       // prot
    newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
    newregs.r8 = -1;                           // fd
    newregs.r9 = 0;                            //  offset

    uint8_t old_word[8];
    uint8_t new_word[8];
    new_word[0] = 0x0f; // SYSCALL
    new_word[1] = 0x05; // SYSCALL
    new_word[2] = 0xff; // JMP %rax
    new_word[3] = 0xe0; // JMP %rax

    // insert the SYSCALL instruction into the process, and save the old word
    if (poke_text(pid, rip, new_word, old_word, sizeof(new_word))) {
      goto fail;
    }

    // set the new registers with our syscall arguments
    setregs(pid, &newregs);

    // invoke mmap(2)
    if (singlestep(pid)) {
        goto fail;
    }

    // read the new register state, so we can see where the mmap went
    getregs(pid, &newregs);

    // this is the address of the memory we allocated
    void *mmap_memory = (void *)newregs.rax;
    if (mmap_memory == (void *)-1) {
        // log_info("failed to mmap\n");
        goto fail;
    }
    // log_info("allocated memory at  %p\n", mmap_memory);
    // log_info("rip is now %p\n", (void *)newregs.rip);

    // log_info("executing jump to mmap region\n");
    if (singlestep(pid)) {
        goto fail;
    }

    getregs(pid, &newregs);
    if (newregs.rip == (long)mmap_memory) {
        // log_info("successfully jumped to mmap area\n");
    } else {
        // log_info("unexpectedly jumped to %p\n", (void *)newregs.rip);
        goto fail;
    }

    // pivot stack into the mmap area
    // newregs.rsp = mmap_memory + PAGE_SIZE - STACK_SIZE - 0x20;
    // newregs.rbp = mmap_memory + PAGE_SIZE - 0x20;

    setregs(pid, &newregs);
    // log_info("set %%rsp to %p\n", (void *)newregs.rsp);
    // log_info("set %%rbp to %p\n", (void *)newregs.rbp);

  
    // update the mmap area with the shellcode
    // log_info("inserting code/data with len %d into the mmap area at %p\n", shellcode_len, mmap_memory);
    // for (int i = 0; i < strlen(shellcode); i++) {
    //     // log_info("inserting byte %x\n", shellcode[i]);
    // }
    if (poke_text(pid, mmap_memory, shellcode, NULL, shellcode_len)) {
        goto fail;
    }

    if (poke_text(pid, rip, new_word, NULL, sizeof(new_word))) {
        goto fail;
    }

    // continue the program, and wait for the trap
    // log_info("continuing execution\n");
    cont(pid);

    getregs(pid, &newregs);
    newregs.rax = (long)rip;
    // newregs.rbp = (long)rbp;
    // newregs.rsp = (long)rsp;

    setregs(pid, &newregs);

    new_word[0] = 0xff; // JMP %rax
    new_word[1] = 0xe0; // JMP %rax
    poke_text(pid, (void *)newregs.rip, new_word, NULL, sizeof(new_word));

    // log_info("jumping back to original rip\n");
    if (singlestep(pid)) {
        goto fail;
    }
    getregs(pid, &newregs);

    if (newregs.rip == (long)rip) {
        // log_info("successfully jumped back to original %%rip at %p\n", rip);
    } else {
        // log_info("unexpectedly jumped to %p (expected to be at %p)\n",
            //  (void *)newregs.rip, rip);
        goto fail;
    }

    // unmap the memory we allocated
    newregs.rax = 11;                // munmap
    newregs.rdi = (long)mmap_memory; // addr
    newregs.rsi = MMAP_SZ;         // size
    setregs(pid, &newregs);

    // make the system call
    // log_info("making call to mmap\n");
    if (singlestep(pid)) {
      goto fail;
    }
    getregs(pid, &newregs);
    // log_info("munmap returned with status %llu\n", newregs.rax);

    // log_info("restoring old text at %p\n", rip);
    poke_text(pid, rip, old_word, NULL, sizeof(old_word));

    // log_info("restoring old registers\n");
    setregs(pid, &oldregs);

    // detach the process
    // log_info("detaching\n");
    detach(pid);
    return 0;

fail:
    poke_text(pid, rip, old_word, NULL, sizeof(old_word));
    detach(pid);
    return 1;
}
