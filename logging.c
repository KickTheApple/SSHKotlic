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
#include <cjson/cJSON.h>

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

int userData_log(userData* user_data, char* event_type) {

    time_t current_time = time(NULL);
    struct tm current_time_formated;
    localtime_r(&current_time, &current_time_formated);
    char currentBuffer[64];
    strftime(currentBuffer, sizeof(currentBuffer), "%Y-%m-%d %H:%M:%S", &current_time_formated);

    struct tm timeOfBirth_formated;
    localtime_r(&(user_data->timeOfBirth), &timeOfBirth_formated);
    char beginningBuffer[64];
    strftime(beginningBuffer, sizeof(beginningBuffer), "%Y-%m-%d %H:%M:%S", &timeOfBirth_formated);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "event_name", event_type);
    cJSON_AddStringToObject(json, "event_time", currentBuffer);

    if (user_data->timeOfBirth) cJSON_AddStringToObject(json, "start_time", beginningBuffer);
    if (user_data->id) cJSON_AddStringToObject(json, "id", user_data->id);
    if (user_data->ip) cJSON_AddStringToObject(json, "ip", user_data->ip);
    if (user_data->containerID) cJSON_AddStringToObject(json, "container", user_data->containerID);
    if (user_data->username) cJSON_AddStringToObject(json, "username", user_data->username);
    if (user_data->password) cJSON_AddStringToObject(json, "password", user_data->password);
    char *json_str = cJSON_PrintUnformatted(json);

    FILE *fp = fopen("events.json", "a");
    if (fp == NULL) {
        printf("Error: Unable to open the file.\n");
        return 1;
    }
    printf("%s\n", json_str);
    fprintf(fp, "%s\n", json_str);
    fclose(fp);

    cJSON_free(json_str);
    cJSON_Delete(json);
    return 0;
}