#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "../hijacker/shellcode.h"

int main(void)
{
    void *ptr = mmap(0, strlen(shellcode), PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    fprintf(stdout,"Length: %d\n", shellcode_len);
    memcpy(ptr, shellcode, shellcode_len);
    ((void(*)())ptr)();
    return 0;
}

