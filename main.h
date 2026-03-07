//
// Created by domenic on 3/7/26.
//

#ifndef SSHKOTLIC_MAIN_H
#define SSHKOTLIC_MAIN_H

struct serveringData {
    WOLFSSH* wolfServer;
    WOLFSSH_CTX* wolfContext;

    int bashInstance;
    int bashCommunicator;

    int isOver;

    int socketFD;
    int ipAddress;
    int port;
} typedef serverData;

struct useringData {
    time_t timeOfBirth;
    char* id;
    char* ip;
    char* keyAlgo;
    char* username;
    char* password;
} typedef userData;

void* read_pass(void* args);
void* write_pass(void* args);
int sock_maker();
int key_master(WOLFSSH_CTX*wolfssh_ctx, const char* name);

#endif //SSHKOTLIC_MAIN_H