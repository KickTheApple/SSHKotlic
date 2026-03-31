//
// Created by domenic on 3/7/26.
//

#include "main.h"
#include "logging.h"

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

    int logStatus = userData_log(user_data, "auth_success");
    if (logStatus != 0) {
        printf("ERROR: Failed to preform first contact log\n");
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}