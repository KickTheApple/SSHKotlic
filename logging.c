//
// Created by domenic on 3/7/26.
//

#include <cjson/cJSON.h>

#include "main.h"
#include "logging.h"
#include "base64.h"

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

int bashinput_log(byte* data, userData* user_data) {
    time_t current_time = time(NULL);
    struct tm current_time_formated;
    localtime_r(&current_time, &current_time_formated);
    char currentBuffer[64];
    strftime(currentBuffer, sizeof(currentBuffer), "%Y-%m-%d %H:%M:%S", &current_time_formated);

    cJSON* json = cJSON_CreateObject();

    cJSON_AddStringToObject(json, "event_name", "bash_data");
    cJSON_AddStringToObject(json, "event_time", currentBuffer);

    cJSON_AddStringToObject(json, "container_id", user_data->containerID);
    cJSON_AddStringToObject(json, "session_id", user_data->id);

    char* encoded_data = base64_encode((char*) data);
    cJSON_AddStringToObject(json, "bash_data", encoded_data);

    char* json_str = cJSON_PrintUnformatted(json);
    fwrite(json_str, 1, strlen(json_str), user_data->bash_file);
    fprintf(user_data->bash_file, "\n");

    free(encoded_data);
    cJSON_free(json_str);
    cJSON_Delete(json);
    return 0;
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
    if (user_data->id) cJSON_AddStringToObject(json, "session_id", user_data->id);
    if (user_data->ip) cJSON_AddStringToObject(json, "src_ip", user_data->ip);
    if (user_data->containerID) cJSON_AddStringToObject(json, "container_id", user_data->containerID);
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