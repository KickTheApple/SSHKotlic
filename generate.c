//
// Created by domenic on 3/31/26.
//

#include "generate.h"

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <wolfssh/ssh.h>

char* generate_session_id(int length) {
    char* newID = malloc(length+1);
    if (newID == NULL) {
        printf("ERROR: Couldn't allocate memory for new ID\n");
        return NULL;
    }

    for (int i = 0; i < length; i++) {
        newID[i] = '0' + rand() % ('9' - '0' + 1);
    }
    newID[length] = '\0';

    return newID;
}

int generate_socketFD() {

    int status = 0;
    int socketFD = 0;
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD == -1) {
        printf("ERROR: Failed to open socket\n");
        return -1;
    }

    //    int opt = 1;
    //    setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in socketInfo = {0};
    socketInfo.sin_family = AF_INET;
    socketInfo.sin_port = htons(22);
    socketInfo.sin_addr.s_addr = htonl(0);

    status = bind(socketFD, (struct sockaddr *) &socketInfo, sizeof(struct sockaddr_in));
    if (status == -1) {
        printf("ERROR: Failed to bind socket\n");
        return -1;
    }

    status = listen(socketFD, SOMAXCONN);
    if (status == -1) {
        printf("ERROR: Failed to listen on socket\n");
        return -1;
    }

    return socketFD;

}

int generate_SSH_Key(WOLFSSH_CTX*wolfssh_ctx, const char* name) {

    byte* keyData = malloc(4096);
    word32 keySize;
    const byte* typeData = malloc(4096);
    word32 typeSize;
    byte privateState;

    int funcState = wolfSSH_ReadKey_file(name, &keyData, &keySize, &typeData, &typeSize, &privateState, NULL);
    if (funcState != WS_SUCCESS) {
        printf("wolfSSH_ReadKey_file failed: %d\n", funcState);
        return funcState;
    }

    printf("LENGTH OF KEY IS: %d\n", keySize);

    int ret = wolfSSH_CTX_UsePrivateKey_buffer(wolfssh_ctx, keyData, keySize, WOLFSSH_FORMAT_ASN1);
    free(keyData);
    //free((void*) typeData);

    if (ret != WS_SUCCESS) {
        printf("wolfSSH_CTX_UsePrivateKey_buffer failed: %d\n", ret);
        return ret;
    }

    return WS_SUCCESS;
}