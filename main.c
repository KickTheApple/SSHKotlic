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
#include <sys/inotify.h>
#include <arpa/inet.h>
#include <poll.h>
#include <cjson/cJSON.h>
#include <wait.h>
#include <pthread.h>
#include <hiredis/hiredis.h>

#include "callbacks.h"
#include "logging.h"
#include "main.h"

serverData server_data;
userData user_data;

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    pcap_dump((u_char*) server_data.pcapDumper, header, packet);
}

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

int kill_all_user_data(userData* billData) {
    if (billData->id) free(billData->id);
    if (billData->ip) free(billData->ip);
    if (billData->keyAlgo) free(billData->keyAlgo);
    if (billData->username) free(billData->username);
    if (billData->password) free(billData->password);
    if (billData->containerID) free(billData->containerID);
    return 0;
}

void signal_catcher(int signal) {
    close(server_data.socketFD);
    wolfSSH_CTX_free(server_data.wolfContext);
    if (server_data.wolfServer) {
        if (server_data.bashCommunicator) {
            wolfSSH_stream_exit(server_data.wolfServer, 130);
            close(server_data.bashCommunicator);
            sleep(2);
        }
        wolfSSH_free(server_data.wolfServer);
    }
    if (server_data.bashInstance) stop_container(user_data.containerID);
    wolfSSH_Cleanup();
    pcap_dump_close(server_data.pcapDumper);
    pcap_close(server_data.pcapHandle);
    redisFree(server_data.redisConn);
    kill_all_user_data(&user_data);
    exit(130);
}

int shutdown_routine_yes_user(userData* bill_data) {
    if (server_data.bashInstance) stop_container(bill_data->containerID);
    wolfSSH_free(server_data.wolfServer);
    wolfSSH_CTX_free(server_data.wolfContext);
    wolfSSH_Cleanup();
    pcap_dump_close(server_data.pcapDumper);
    pcap_close(server_data.pcapHandle);
    redisFree(server_data.redisConn);
    kill_all_user_data(bill_data);
    return 0;
}

int shutdown_routine_no_user() {
    wolfSSH_free(server_data.wolfServer);
    wolfSSH_CTX_free(server_data.wolfContext);
    wolfSSH_Cleanup();
    pcap_dump_close(server_data.pcapDumper);
    pcap_close(server_data.pcapHandle);
    redisFree(server_data.redisConn);
    return 0;
}

char* get_redis_entry(char* key) {
    char* redis_value = malloc(65);

    redisReply* reply = redisCommand(server_data.redisConn, "get %s", key);
    printf("%s\n", key);
    if (reply == NULL) {
        printf("Redis Reply couldn't have been created\n");
        free(redis_value);
        return NULL;
    }
    if (reply->str == NULL) {
        printf("Redis entry not found\n");
        freeReplyObject(reply);
        free(redis_value);
        return NULL;
    }
    printf("%s\n", reply->str);
    memcpy(redis_value, reply->str, reply->len < 64 ? reply->len : 64);
    redis_value[reply->len < 64 ? reply->len : 64] = '\0';

    freeReplyObject(reply);
    printf("Redis entry successfully found\n");
    return redis_value;
}

int is_redis_entry(char* key) {
    printf("DO WE GET HERE\n");
    redisReply* reply = redisCommand(server_data.redisConn, "get %s", key);
    printf("%s\n", key);
    if (reply == NULL) {
        printf("WE DO DO NOT HAVE\n");
        return -1;
    }
    if (reply->str == NULL) {
        printf("We did not find value\n");
        freeReplyObject(reply);
        return 0;
    }
    printf("%s\n", reply->str);
    freeReplyObject(reply);
    printf("WE DO GET HERE\n");
    return 1;
}

int create_redis_entry(char* key, char* value) {
    redisReply* reply = redisCommand(server_data.redisConn, "set %s %s", key, value);
    if (strcmp(reply->str, "OK") == 0) {
        freeReplyObject(reply);
        return 1;
    }
    freeReplyObject(reply);
    return 0;
}

void *pcap_pass(void* args) {
    pcap_loop(server_data.pcapHandle, 0, got_packet, NULL);
    return NULL;
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
            wolfSSH_stream_exit(server_data.wolfServer, 0);
            break;
        }
    }
    server_data.isOver = 1;
    return NULL;
}

/*
char* get_containerID(char* cidfile) {
    int failCount = 0;
    char* container_hash = malloc(65);
    while (1) {
        FILE* f = fopen(cidfile, "r");
        if (!f) {
            printf("FAILED TO OPEN %s\n", cidfile);
            failCount++;
            if (failCount == 50) {
                free(container_hash);
                return NULL;
            }
            usleep(100000);
            continue;
        }
        size_t result = fread(container_hash, 1, 64, f);
        if (result == 0) {
            printf("Failed to read container hash id\n");
            fclose(f);
            usleep(100000);
            continue;
        }
        printf("Success to read container hash id\n");
        fclose(f);
        return container_hash;
    }
}
*/

int basher3_ItsBash(int *master, char* filename_id) {
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

    server_data.redisConn = redisConnect("127.0.0.1", 6379);
    if (server_data.redisConn  == NULL || server_data.redisConn ->err) {
        if (server_data.redisConn) {
            printf("Connection error: %s", server_data.redisConn ->errstr);
            redisFree(server_data.redisConn );
        } else {
            printf("Connection error: can't allocate redis context");
        }
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    server_data.pcapHandle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (server_data.pcapHandle == NULL) {
        printf("ERROR: Couldn't open device for packet listening: %s\n", errbuf);
        redisFree(server_data.redisConn);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(server_data.pcapHandle, &fp, "port 22", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("ERROR: Couldn't parse filter for PCAP: %s\n", pcap_geterr(server_data.pcapHandle));
        pcap_close(server_data.pcapHandle);
        redisFree(server_data.redisConn);
        return 1;
    }

    if (pcap_setfilter(server_data.pcapHandle, &fp) == -1) {
        printf("ERROR: Couldn't attach filter to network listener: %s\n", pcap_geterr(server_data.pcapHandle));
        pcap_freecode(&fp);
        pcap_close(server_data.pcapHandle);
        redisFree(server_data.redisConn);
        return 1;
    }
    pcap_freecode(&fp);

    server_data.pcapDumper = pcap_dump_open(server_data.pcapHandle, "packets.pcap");
    if (server_data.pcapDumper == NULL) {
        printf("ERROR: Couldn't instancialize the dumper: %s\n", pcap_geterr(server_data.pcapHandle));
        pcap_close(server_data.pcapHandle);
        redisFree(server_data.redisConn);
        return 1;
    }

    pthread_t networker;
    pthread_create(&networker, NULL, pcap_pass, NULL);

    server_data.isOver = 0;

    server_data.ipAddress = 0;
    server_data.port = 22;
    server_data.socketFD = sock_maker();
    if (server_data.socketFD == -1) {
        printf("SERVER TERMINATED\n");
        pcap_dump_close(server_data.pcapDumper);
        pcap_close(server_data.pcapHandle);
        redisFree(server_data.redisConn);
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
        close(server_data.socketFD);
        wolfSSH_CTX_free(server_data.wolfContext);
        wolfSSH_Cleanup();

        pcap_dump_close(server_data.pcapDumper);
        pcap_close(server_data.pcapHandle);
        redisFree(server_data.redisConn);
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
            shutdown_routine_no_user();
            return 1;
        }
        if (vilca > 0) {
            close(clientFD);
            continue;
        }

        user_data.timeOfBirth = time(NULL);
        user_data.id = generate_session_id(10);
        user_data.ip = whatIsMyIP(clientFD);
        user_data.keyAlgo = NULL;
        user_data.username = NULL;
        user_data.password = NULL;
        user_data.containerID = NULL;

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

        char* bashID = get_redis_entry(user_data.ip);
        if (bashID == NULL) {
            char* cidfile = malloc(65);
            snprintf(cidfile, 65, "bashid_%s", user_data.id);
            user_data.containerID = cidfile;

            server_data.bashCommunicator = -1;
            server_data.bashInstance = basher3_ItsBash(&server_data.bashCommunicator, user_data.containerID);
        } else {
            user_data.containerID = bashID;

            server_data.bashCommunicator = -1;
            server_data.bashInstance = start_container(&server_data.bashCommunicator, user_data.containerID);
        }

        if (server_data.bashInstance < 0) {
            printf("ERROR: Fork operation failed during bash execution\n");
            shutdown_routine_yes_user(&user_data);
            return 0;
        }
        if (server_data.bashCommunicator < 0) {
            printf("ERROR: Communication point could not be established\n");
            shutdown_routine_yes_user(&user_data);
            return 0;
        }

        if (bashID == NULL) {
            int redis_creation = create_redis_entry(user_data.ip, user_data.containerID);
            if (!redis_creation) {
                printf("Redis couldn't create a new entry");
                shutdown_routine_yes_user(&user_data);
                return 1;
            }
        }

        pthread_t reader;
        pthread_t writer;

        pthread_create(&reader, NULL, read_pass, NULL);
        pthread_create(&writer, NULL, write_pass, NULL);

        while (!server_data.isOver) {
        }

        shutdown_routine_yes_user(&user_data);
        return 0;
    }
}