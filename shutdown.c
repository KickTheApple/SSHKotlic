//
// Created by domenic on 3/31/26.
//

#include <stdlib.h>
#include <unistd.h>
#include <wolfssh/ssh.h>

#include "container.h"
#include "logging.h"

#include "shutdown.h"

#include <sys/wait.h>

extern serverData server_data;
extern userData user_data;

int kill_all_user_data(userData* billData) {
    userData_log(billData, "connection_end");

    if (billData->id) free(billData->id);
    if (billData->ip) free(billData->ip);
    if (billData->keyAlgo) free(billData->keyAlgo);
    if (billData->username) free(billData->username);
    if (billData->password) free(billData->password);
    if (billData->containerID) free(billData->containerID);
    if (billData->bash_file) fclose(billData->bash_file);
    return 0;
}

void fork_catcher(int signal) {
    printf("Fork is about to fall of the counter %d\n", server_data.forkCount);
    waitpid(-1, NULL, WNOHANG);
    server_data.forkCount--;

    printf("Fork fell of the counter %d\n", server_data.forkCount);
}

void signal_catcher(int signal) {
    printf("Fork count is: %d\n", server_data.forkCount);
    while (server_data.forkCount) {
    }
    close(server_data.socketFD);
    if (server_data.wolfServer) {
        if (server_data.bashCommunicator) {
            wolfSSH_stream_exit(server_data.wolfServer, 130);
            close(server_data.bashCommunicator);
            // TODO: REPLACE SLEEP WITH Conditional joins for Reader and Writer thread
            sleep(2);
        }
        wolfSSH_free(server_data.wolfServer);
    }
    wolfSSH_CTX_free(server_data.wolfContext);
    wolfSSH_Cleanup();

    if (server_data.bashInstance) stop_container(user_data.containerID);

    if (server_data.pcapHandle != NULL && server_data.pcapDumper != NULL) {
        pcap_breakloop(server_data.pcapHandle);
        pthread_join(user_data.networker, NULL);
    }
    if (server_data.pcapDumper != NULL) pcap_dump_close(server_data.pcapDumper);
    if (server_data.pcapHandle != NULL) pcap_close(server_data.pcapHandle);
    if (server_data.pcapHandle != NULL && server_data.pcapDumper != NULL) pcap_sender(&user_data);

    redisFree(server_data.redisConn);
    curl_global_cleanup();

    kill_all_user_data(&user_data);
    exit(130);
}

int shutdown_routine_yes_user(userData* bill_data) {
    if (server_data.bashInstance) stop_container(bill_data->containerID);
    close(server_data.socketFD);
    if (server_data.wolfServer != NULL) wolfSSH_free(server_data.wolfServer);
    wolfSSH_CTX_free(server_data.wolfContext);
    wolfSSH_Cleanup();

    if (server_data.pcapHandle != NULL && server_data.pcapDumper != NULL) {
        pcap_breakloop(server_data.pcapHandle);
        pthread_join(bill_data->networker, NULL);
    }
    if (server_data.pcapDumper != NULL) pcap_dump_close(server_data.pcapDumper);
    if (server_data.pcapHandle != NULL) pcap_close(server_data.pcapHandle);
    if (server_data.pcapHandle != NULL && server_data.pcapDumper != NULL) pcap_sender(&user_data);

    redisFree(server_data.redisConn);
    curl_global_cleanup();

    kill_all_user_data(bill_data);
    return 0;
}

int shutdown_routine_no_user() {
    close(server_data.socketFD);
    wolfSSH_CTX_free(server_data.wolfContext);
    wolfSSH_Cleanup();

    redisFree(server_data.redisConn);
    curl_global_cleanup();
    return 0;
}