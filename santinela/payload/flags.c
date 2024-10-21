#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>

int main() {
    //int fd = open("/tmp/caca1.txt", O_CREAT | O_RDWR, 0644);

    //write(fd, "flag{d0nt_f0rg3t_t0_cl0s3_th3_f1l3}", 35);
    printf("%d", FD_CLOEXEC);
    // execveat(fd, "", NULL, NULL, 0x1000);

}