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