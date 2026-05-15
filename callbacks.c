//
// Created by domenic on 3/7/26.
//

#include "main.h"
#include "logging.h"
#include "lookup.h"

int is_credential_match(char* value) {
    char validCombo[3][10] = {"admin", "root", "user"};
    for (int i = 0; i < 3; i++) {
        if (strcmp(value, validCombo[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

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

    char credential_field[65];
    char credential_combo[33];
    snprintf(credential_field, 64, "%s-cred", user_data->ip);
    if (is_redis_entry(credential_field)) {
        snprintf(credential_combo, 32, "%s:%s", user_data->username, user_data->password);
        char* activated_credentials = get_redis_entry(credential_field);
        if (strcmp(credential_combo, activated_credentials) == 0) {
            free(activated_credentials);
            int logStatus = userData_log(user_data, "auth_success");
            if (logStatus != 0) {
                printf("ERROR: Failed to preform first contact log\n");
            }
            return WOLFSSH_USERAUTH_SUCCESS;
        }

        free(activated_credentials);
        int logStatus = userData_log(user_data, "auth_failure");
        if (logStatus != 0) {
            printf("ERROR: Failed to preform first contact log\n");
        }
        return WOLFSSH_USERAUTH_FAILURE;
    }
    if (is_credential_match(user_data->username) && is_credential_match(user_data->password)) {
        int logStatus = userData_log(user_data, "auth_success");
        if (logStatus != 0) {
            printf("ERROR: Failed to preform first contact log\n");
        }

        snprintf(credential_combo, 32, "%s:%s", user_data->username, user_data->password);
        create_redis_entry(credential_field, credential_combo);
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    int logStatus = userData_log(user_data, "auth_failure");
    if (logStatus != 0) {
        printf("ERROR: Failed to preform first contact log\n");
    }
    return WOLFSSH_USERAUTH_FAILURE;
}