//
// Created by domenic on 3/7/26.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unctrl.h>
#include <wolfssh/ssh.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <math.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/agent.h>
#include <wolfssh/port.h>
#include <wolfssh/test.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pty.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <poll.h>
#include "main.h"
#include "logging.h"
#include <cjson/cJSON.h>


int kotlic_ChannelCloseCallback(WOLFSSH_CHANNEL* channel, void* ctx) {
    printf("CHANNEL WILL BE CLOSED\n");
    return 0;
}

int kotlic_ChannelEOFCallback(WOLFSSH_CHANNEL* channel, void* ctx) {
    printf("CHANNEL REACHED CONCLUSSION\n");
    return 0;
}

int kotlic_ChannelOpenCallback(WOLFSSH_CHANNEL* channel, void* ctx) {
    printf("CHANNEL WILL BE OPENNED\n");

    return 0;
}

int kotlic_ChannelRequestCallback(WOLFSSH_CHANNEL* channel, void* ctx) {
    printf("CHANNEL REQUEST RECIEVED\n");
    return 0;
}

int kotlic_UserAuthCallback(byte authType, WS_UserAuthData* authData, void* ctx) {
    printf("Auth type: %d\n", authType);
    if (authType == WOLFSSH_USERAUTH_KEYBOARD) return WOLFSSH_USERAUTH_FAILURE;
    userData* user_data = ctx;
    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        WS_UserAuthData_PublicKey auth_data_public_key = authData->sf.publicKey;

        char* keyerWord = malloc(auth_data_public_key.publicKeyTypeSz+1);
        memcpy(keyerWord, (const char *) auth_data_public_key.publicKeyType, auth_data_public_key.publicKeyTypeSz);
        keyerWord[auth_data_public_key.publicKeyTypeSz] = '\0';
        user_data->keyAlgo = keyerWord;

        return WOLFSSH_USERAUTH_FAILURE;
    }
    WS_UserAuthData_Password auth_data_password = authData->sf.password;

    char* useringWord = malloc(authData->usernameSz+1);
    strncpy(useringWord, (const char *) authData->username, authData->usernameSz);
    useringWord[authData->usernameSz] = '\0';
    user_data->username = useringWord;

    char* passingWord = malloc(auth_data_password.passwordSz+1);
    memcpy(passingWord, (const char *) auth_data_password.password, auth_data_password.passwordSz);
    passingWord[auth_data_password.passwordSz] = '\0';
    user_data->password = passingWord;

    int logStatus = secondContactLog(user_data);
    if (logStatus != 0) {
        printf("ERROR: Failed to preform first contact log\n");
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}