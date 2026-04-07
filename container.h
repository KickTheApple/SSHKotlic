//
// Created by domenic on 3/23/26.
//

#ifndef SSHKOTLIC_CONTAINER_H
#define SSHKOTLIC_CONTAINER_H

int stop_container(char* containerID);
int start_container(int* master, char* containerID);
int create_container(int *master, char* filename_id);

#endif //SSHKOTLIC_CONTAINER_H