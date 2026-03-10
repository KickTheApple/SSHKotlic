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
#include <cjson/cJSON.h>
#include <pthread.h>

#include "callbacks.h"
#include "logging.h"
#include "main.h"

serverData server_data;

void signal_catcher(int signal) {
    close(server_data.socketFD);
    wolfSSH_CTX_free(server_data.wolfContext);
    if (server_data.wolfServer) wolfSSH_free(server_data.wolfServer);
    if (server_data.bashCommunicator) {
        close(server_data.bashCommunicator);
        sleep(2);
    }
    if (server_data.bashInstance) kill(server_data.bashInstance, SIGTERM);
    wolfSSH_Cleanup();
    exit(130);
}

int kill_all_user_data(userData* billData) {
    if (billData->id) free(billData->id);
    if (billData->ip) free(billData->ip);
    if (billData->keyAlgo) free(billData->keyAlgo);
    if (billData->username) free(billData->username);
    if (billData->password) free(billData->password);
    return 0;
}

void* read_pass(void* args) {
    byte channelBuffer[1024];
    while (1) {
        int ret = wolfSSH_stream_read(server_data.wolfServer, channelBuffer, sizeof(channelBuffer));
        if (ret > 0) {
            printf("%s\n", (char*) channelBuffer);
            write(server_data.bashCommunicator, channelBuffer, ret);
            continue;
        }
        if (ret == 0) {
            printf("the value of ret is 0\n");
        }
        if (ret < 0) {
            printf("the value of ret is less than 0 - RRRR\n");
            break;
        }
    }
    return NULL;
}

void* write_pass(void* args) {
    byte channelBuffer[1024];
    while (1) {
        long ret = read(server_data.bashCommunicator, channelBuffer, sizeof(channelBuffer));
        if (ret > 0) {
            printf("%s\n", (char*) channelBuffer);
            wolfSSH_stream_send(server_data.wolfServer, channelBuffer, ret);
            continue;
        }
        if (ret == 0) {
            printf("the value of ret is 0\n");
        }
        if (ret < 0) {
            printf("the value of ret is less than 0 - WWWW\n");
            break;
        }
    }
    return NULL;
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
    //free((void*) typeData);

    if (ret != WS_SUCCESS) {
        printf("wolfSSH_CTX_UsePrivateKey_buffer failed: %d\n", ret);
        return ret;
    }

    return WS_SUCCESS;
}

int main(int argc, char* args[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, signal_catcher);
    signal(SIGCHLD, SIG_IGN);

    srand(time(NULL));

    server_data.isOver = 0;

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
        wolfSSH_CTX_free(server_data.wolfContext);
        wolfSSH_Cleanup();
        return keyStatus;
    }

    int clientFD;
    struct sockaddr_in clientSock;
    socklen_t clientSize = sizeof(struct sockaddr_in);
    while (1) {
        clientFD = accept(server_data.socketFD, (struct sockaddr *) &clientSock, &clientSize);
        if (clientFD < 0) {
            printf("ERROR: Failed to accept connection\n");
            continue;
        }

        int vilca = fork();
        if (vilca < 0) {
            printf("ERROR: Failed to launch fork operation on accepted connection\n");
            wolfSSH_free(server_data.wolfServer);
            wolfSSH_CTX_free(server_data.wolfContext);
            wolfSSH_Cleanup();
            return 1;
        }
        if (vilca > 0) {
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

        server_data.bashCommunicator = -1;
        server_data.bashInstance = basher3_ItsBash(&server_data.bashCommunicator);

        if (server_data.bashInstance < 0) {
            printf("ERROR: Fork operation failed during bash execution\n");
            wolfSSH_free(server_data.wolfServer);
            wolfSSH_CTX_free(server_data.wolfContext);
            wolfSSH_Cleanup();
            kill_all_user_data(&user_data);
            return 0;
        }
        if (server_data.bashCommunicator < 0) {
            printf("ERROR: Communication point could not be established\n");
            wolfSSH_free(server_data.wolfServer);
            wolfSSH_CTX_free(server_data.wolfContext);
            wolfSSH_Cleanup();
            kill_all_user_data(&user_data);
            return 0;
        }

        pthread_t reader;
        pthread_t writer;

        pthread_create(&reader, NULL, read_pass, NULL);
        pthread_create(&writer, NULL, write_pass, NULL);

        while (!server_data.isOver) {
        }
        
        wolfSSH_free(server_data.wolfServer);
        wolfSSH_CTX_free(server_data.wolfContext);
        wolfSSH_Cleanup();
        kill_all_user_data(&user_data);
        return 0;
    }
}