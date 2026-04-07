//
// Created by domenic on 3/23/26.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pty.h>
#include <wait.h>

#include "container.h"

int stop_container(char* containerID) {
    int spork = fork();
    if (spork == 0) {
        execl("/usr/bin/docker", "docker", "stop", containerID, (char*) NULL);
        exit(1);
    }
    waitpid(spork, NULL, 0);
    return 0;
}

int start_container(int* master, char* containerID) {
    int masterPd;
    int forky = forkpty(&masterPd, NULL, NULL, NULL);
    if (forky == -1) {
        printf("Problem with Smoking Pipes\n");
        return -1;
    }
    if (forky == 0) {
        execl("/usr/bin/docker", "docker", "start", "-ai", containerID, (char *) NULL);
        printf("bin bang bash error\n");
        exit(1);
    }
    *master = masterPd;
    return forky;
}

int create_container(int *master, char* filename_id) {
    int masterPd;
    int forky = forkpty(&masterPd, NULL, NULL, NULL);
    if (forky == -1) {
        printf("Problem with Smoking Pipes\n");
        return -1;
    }
    if (forky == 0) {
        execl("/usr/bin/docker", "docker", "run", "-ti", "--name", filename_id, "--entrypoint", "/bin/sh", "--net", "none", "bash", "-i", (char *) NULL);
        printf("bin bang bash error\n");
        exit(1);
    }
    *master = masterPd;
    return forky;
}