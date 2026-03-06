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

#include <cjson/cJSON.h>

struct serveringData {
    WOLFSSH* wolfServer;
    WOLFSSH_CTX* wolfContext;

    int socketFD;
    int ipAddress;
    int port;

    int nextSession;
} typedef serverData;

struct useringData {
    time_t timeOfBirth;
    char* id;
    char* ip;
    char* keyAlgo;
    char* username;
    char* password;
} typedef userData;

void signal_catcher(int signal) {

}

int basher3_ItsBash(int *master) {

    int masterPd;
    int forky = forkpty(&masterPd, NULL, NULL, NULL);

    if (forky == -1) {
        printf("Problem with Smoking Pipes\n");
        return -1;
    }

    if (forky == 0) {

        execl("/usr/bin/docker", "docker", "run", "-ti", "--rm", "--entrypoint", "/bin/sh", "--net", "none", "bash", "-i", (char *) NULL);
        printf("bin bang bash error\n");
        exit(1);

    }

    *master = masterPd;
    return forky;

}

int kill_all_user_data(userData billData) {
    if (billData.id) {
        free(billData.id);
    }
    if (billData.ip) {
        free(billData.ip);
    }
    if (billData.keyAlgo) {
        free(billData.keyAlgo);
    }
    if (billData.username) {
        free(billData.username);
    }
    if (billData.password) {
        free(billData.password);
    }
}

char* generate_session_id(int length) {
    char* newID = malloc(length+1);
    if (newID == NULL) {
        printf("ERROR: Couldn't allocate memory for new ID\n");
        return NULL;
    }

    srand(time(NULL));

    for (int i = 0; i < length; i++) {
        newID[i] = '0' + rand() % ('0' - '9' + 1);
    }
    newID[length] = '\0';

    return newID;
}

int secondContactLog(userData* user_data) {
    struct tm timeOfBirth_formated;
    localtime_r(&(user_data->timeOfBirth), &timeOfBirth_formated);

    char timeBuffer[64];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &timeOfBirth_formated);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "event", "sign-in");
    cJSON_AddStringToObject(json, "id", user_data->id);
    cJSON_AddStringToObject(json, "time", timeBuffer);
    cJSON_AddStringToObject(json, "ip", user_data->ip);
    cJSON_AddStringToObject(json, "username", user_data->username);
    cJSON_AddStringToObject(json, "password", user_data->password);
    char *json_str = cJSON_Print(json);

    FILE *fp = fopen("events.json", "a");
    if (fp == NULL) {
        printf("Error: Unable to open the file.\n");
        return 1;
    }
    printf("%s\n", json_str);
    fputs(json_str, fp);
    fclose(fp);

    cJSON_free(json_str);
    cJSON_Delete(json);
    return 0;
}

int firstContactLog(userData* user_data) {

    struct tm timeOfBirth_formated;
    localtime_r(&(user_data->timeOfBirth), &timeOfBirth_formated);

    char timeBuffer[64];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &timeOfBirth_formated);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "event", "connection");
    cJSON_AddStringToObject(json, "id", user_data->id);
    cJSON_AddStringToObject(json, "time", timeBuffer);
    cJSON_AddStringToObject(json, "ip", user_data->ip);

    char *json_str = cJSON_Print(json);

    FILE *fp = fopen("events.json", "a");
    if (fp == NULL) {
        printf("Error: Unable to open the file.\n");
        return 1;
    }
    printf("%s\n", json_str);
    fputs(json_str, fp);
    fclose(fp);

    cJSON_free(json_str);
    cJSON_Delete(json);
    return 0;
}

/*
    struct tm timeOfBirth_formated;
    localtime_r(&(user_data->timeOfBirth), &timeOfBirth_formated);

    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeOfBirth_formated);


    FILE* file = fopen("connLog", "a");
    if (file == NULL) {
        printf("ERROR: Failed to open first contact log file\n");
        return 1;
    }
    fprintf(file, "%d:%s:%s:%s\n", user_data->id, buffer, user_data->ip, user_data->keyAlgo);
    fclose(file);

    return 0;
    */

char* whatIsMyIP(int clientFD) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(clientFD, (struct sockaddr *)&addr, &addr_size);
    if (res == -1) {
        printf("ERROR: This is not my IP\n");
        return NULL;
    }
    char *clientip = malloc(INET_ADDRSTRLEN);
    strcpy(clientip, inet_ntoa(addr.sin_addr));
    return clientip;
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

    int logStatus = secondContactLog(user_data);
    if (logStatus != 0) {
        printf("ERROR: Failed to preform first contact log\n");
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}



int sock_maker() {

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

int key_master(WOLFSSH_CTX*wolfssh_ctx, const char* name) {

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
    free((void*) typeData);

    if (ret != WS_SUCCESS) {
        printf("wolfSSH_CTX_UsePrivateKey_buffer failed: %d\n", ret);
        return ret;
    }

    return WS_SUCCESS;
}

int main(int argc, char* args[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, signal_catcher);

    serverData server_data;
    server_data.ipAddress = 0;
    server_data.port = 22;
    server_data.socketFD = sock_maker();
    if (server_data.socketFD == -1) {
        printf("SERVER TERMINATED\n");
        return 1;
    }

    wolfSSH_Init();

    server_data.wolfContext = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    wolfSSH_CTX_SetAlgoListKex(server_data.wolfContext, "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdsa-sha2-nistp256");
    wolfSSH_CTX_SetAlgoListCipher(server_data.wolfContext, "aes128-ctr,aes256-ctr");
    wolfSSH_CTX_SetAlgoListMac(server_data.wolfContext, "hmac-sha2-256,hmac-sha2-512");
    wolfSSH_SetUserAuth(server_data.wolfContext , kotlic_UserAuthCallback);
    wolfSSH_CTX_SetChannelReqExecCb(server_data.wolfContext, kotlic_ChannelRequestCallback);
    wolfSSH_CTX_SetChannelOpenCb(server_data.wolfContext, kotlic_ChannelOpenCallback);
    wolfSSH_CTX_SetChannelCloseCb(server_data.wolfContext, kotlic_ChannelCloseCallback);
    wolfSSH_CTX_SetChannelEofCb(server_data.wolfContext, kotlic_ChannelEOFCallback);

    const char keyFile[] = "./id_ecdsa";

    int keyStatus = key_master(server_data.wolfContext, keyFile);
    if (keyStatus != WS_SUCCESS) {
        printf("ERROR: WE ARE COOKED IF 1\n1");
        return keyStatus;
    }

    int id = 0;

    int clientFD;
    struct sockaddr_in clientSock;
    socklen_t clientSize = sizeof(struct sockaddr_in);
    while (1) {
        clientFD = accept(server_data.socketFD, (struct sockaddr *) &clientSock, &clientSize);
        int vilca = fork();
        if (vilca < 0) {
            break;
        }
        if (vilca > 0) {
            id++;
            continue;
        }

        userData user_data;
        user_data.timeOfBirth = time(NULL);
        user_data.id = generate_session_id(10);
        user_data.ip = whatIsMyIP(clientFD);

        int logStatus = firstContactLog(&user_data);
        if (logStatus != 0) {
            printf("ERROR: Failed to preform first contact log\n");
        }

        server_data.wolfServer = wolfSSH_new(server_data.wolfContext);
        wolfSSH_set_fd(server_data.wolfServer, clientFD);
        wolfSSH_SetUserAuthCtx(server_data.wolfServer, &user_data);
        wolfSSH_SetChannelReqCtx(server_data.wolfServer, &user_data);
        wolfSSH_SetChannelOpenCtx(server_data.wolfServer, &user_data);
        wolfSSH_SetChannelEofCtx(server_data.wolfServer, &user_data);
        wolfSSH_SetChannelCloseCtx(server_data.wolfServer, &user_data);

        int ret = wolfSSH_accept(server_data.wolfServer);
        if (ret == WS_SUCCESS) {
            printf("SUCCESS\n");
        } else {
            printf("FAILURE: %s\n", wolfSSH_get_error_name(server_data.wolfServer));
        }

        int communication = -1;
        int bashInstance = basher3_ItsBash(&communication);
        if (bashInstance < 0) {
            printf("ERROR: Fork operation failed during bash execution\n");
        }
        if (communication < 0) {
            printf("ERROR: Communication point could not be established\n");
            return 0;
        }

        byte channelBuffer[1024];
        while (1) {
            ret = wolfSSH_stream_read(server_data.wolfServer, channelBuffer, sizeof(channelBuffer));
            if (ret > 0) {
                printf("%s\n", (char*) channelBuffer);
            }
        }
        
        wolfSSH_free(server_data.wolfServer);
        break;
    }

    wolfSSH_CTX_free(server_data.wolfContext);
    wolfSSH_Cleanup();
    return 0;
}