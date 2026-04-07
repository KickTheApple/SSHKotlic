#include <signal.h>

#include "container.h"
#include "callbacks.h"
#include "logging.h"
#include "shutdown.h"
#include "lookup.h"
#include "concurrent.h"
#include "generate.h"
#include "main.h"

serverData server_data;
userData user_data;


int main(int argc, char* args[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, signal_catcher);
    signal(SIGCHLD, SIG_IGN);

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

    server_data.pcapHandle = NULL;
    server_data.pcapDumper = NULL;
    server_data.wolfServer = NULL;

    server_data.isOver = 0;
    server_data.ipAddress = 0;
    server_data.port = 22;
    server_data.socketFD = generate_socketFD();
    if (server_data.socketFD == -1) {
        printf("SERVER TERMINATED\n");
        redisFree(server_data.redisConn);
        return 1;
    }

    CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
    if (result != CURLE_OK) {
        printf("ERROR: Couldn't start global curl\n");
        close(server_data.socketFD);

        redisFree(server_data.redisConn);
        return 1;
    }

    user_data.timeOfBirth = 0;

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

    int keyStatus = generate_SSH_Key(server_data.wolfContext, keyFile);
    if (keyStatus != WS_SUCCESS) {
        printf("ERROR: Failed to generate key\n");

        shutdown_routine_no_user();
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

        time_t timerOfStart = time(NULL);
        srand(timerOfStart);

        user_data.timeOfBirth = timerOfStart;
        user_data.id = generate_session_id(10);
        user_data.ip = whatIsMyIP(clientFD, &user_data);
        user_data.keyAlgo = NULL;
        user_data.username = NULL;
        user_data.password = NULL;
        user_data.containerID = NULL;

        int logStatus = userData_log(&user_data, "connection_start");
        if (logStatus != 0) {
            printf("ERROR: Failed to preform first contact log\n");
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        server_data.pcapHandle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
        if (server_data.pcapHandle == NULL) {
            printf("ERROR: Couldn't open device for packet listening: %s\n", errbuf);
            shutdown_routine_yes_user(&user_data);
            return 1;
        }

        char filter_expr[128];
        snprintf(filter_expr, sizeof(filter_expr),
            "(src host %s and src port %d and dst port 22) or "
            "(dst host %s and dst port %d and src port 22)",
            user_data.ip, ntohs(clientSock.sin_port),
            user_data.ip, ntohs(clientSock.sin_port)
        );

        struct bpf_program fp;
        if (pcap_compile(server_data.pcapHandle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            printf("ERROR: Couldn't parse filter for PCAP: %s\n", pcap_geterr(server_data.pcapHandle));
            shutdown_routine_yes_user(&user_data);
            return 1;
        }

        if (pcap_setfilter(server_data.pcapHandle, &fp) == -1) {
            printf("ERROR: Couldn't attach filter to network listener: %s\n", pcap_geterr(server_data.pcapHandle));
            pcap_freecode(&fp);
            shutdown_routine_yes_user(&user_data);
            return 1;
        }
        pcap_freecode(&fp);

        char packet_filename[65];
        snprintf(packet_filename, 64, "network/session_%s.pcap", user_data.id);
        server_data.pcapDumper = pcap_dump_open(server_data.pcapHandle, packet_filename);
        if (server_data.pcapDumper == NULL) {
            printf("ERROR: Couldn't instancialize the dumper: %s\n", pcap_geterr(server_data.pcapHandle));
            shutdown_routine_yes_user(&user_data);
            return 1;
        }

        pthread_create(&user_data.networker, NULL, pcap_thread, NULL);

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
            shutdown_routine_yes_user(&user_data);
            return 1;
        }

        char* bashID = get_redis_entry(user_data.ip);
        if (bashID == NULL) {
            char* cidfile = malloc(65);
            snprintf(cidfile, 65, "bashid_%s", user_data.id);
            user_data.containerID = cidfile;
            userData_log(&user_data, "sign_in_first");

            server_data.bashCommunicator = -1;
            server_data.bashInstance = create_container(&server_data.bashCommunicator, user_data.containerID);
        } else {
            user_data.containerID = bashID;
            userData_log(&user_data, "sign_in_repeat");

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

        pthread_create(&user_data.reader, NULL, read_thread, NULL);
        pthread_create(&user_data.writer, NULL, write_thread, NULL);

        pthread_join(user_data.reader, NULL);
        pthread_join(user_data.writer, NULL);

        shutdown_routine_yes_user(&user_data);
        return 0;
    }
}