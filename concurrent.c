//
// Created by domenic on 3/31/26.
//


#include <pcap/pcap.h>
#include <sys/types.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/types.h>

#include "concurrent.h"
#include "logging.h"
#include "main.h"

extern serverData server_data;
extern userData user_data;

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    pcap_dump((u_char*) server_data.pcapDumper, header, packet);
}

void *pcap_thread(void* args) {
    pcap_loop(server_data.pcapHandle, 0, got_packet, NULL);
    return NULL;
}

void* read_thread(void* args) {
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

void* write_thread(void* args) {
    byte channelBuffer[1024];
    char filename[64];
    snprintf(filename, 64, "terminal/session_%s.log", user_data.id);
    user_data.bash_file = fopen(filename, "w");
    if (user_data.bash_file == NULL) {
        printf("FAILED TO WRITE TO FILE\n");
        return NULL;
    }
    while (1) {
        long ret = read(server_data.bashCommunicator, channelBuffer, sizeof(channelBuffer));
        if (ret > 0) {
            byte converted_channelBuffer[1025];
            memcpy(converted_channelBuffer, channelBuffer, ret);
            converted_channelBuffer[ret] = '\0';

            bashinput_log(converted_channelBuffer, &user_data);
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
    fclose(user_data.bash_file);
    user_data.bash_file = NULL;
    return NULL;
}