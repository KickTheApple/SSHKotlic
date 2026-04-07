//
// Created by domenic on 3/7/26.
//

#include <cjson/cJSON.h>

#include "main.h"
#include "logging.h"
#include "base64.h"

int pcap_sender(userData* user_data) {

    char filename[65];
    snprintf(filename, 64, "network/session_%s.pcap", user_data->id);
    CURL *curler = curl_easy_init();
    if (!curler) {
        printf("EASY FAIL SENDING OF PCAP\n");
        return 1;
    }

    curl_easy_setopt(curler, CURLOPT_URL, "http://localhost:8000/datapot/api/pcap/upload/");
    curl_mime *mime = curl_mime_init(curler);

    curl_mimepart *title_part = curl_mime_addpart(mime);
    curl_mime_name(title_part, "title");
    curl_mime_data(title_part, user_data->id, CURL_ZERO_TERMINATED);

    curl_mimepart *file_part = curl_mime_addpart(mime);
    curl_mime_name(file_part, "file");
    curl_mime_filedata(file_part, filename);

    curl_easy_setopt(curler, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curler, CURLOPT_VERBOSE, 1L);

    CURLcode result = curl_easy_perform(curler);
    curl_mime_free(mime);
    if (result != CURLE_OK) {
        curl_easy_cleanup(curler);

        printf("FAILURE SENDING OF PCAP\n");
        return 1;
    }

    curl_easy_cleanup(curler);

    printf("SUCCESSFUL SENDING OF PCAP\n");
    return 0;

}

char* whatIsMyIP(int clientFD, userData* user_data) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(clientFD, (struct sockaddr *)&addr, &addr_size);

    if (res == -1) {
        printf("ERROR: This is not my IP\n");
        return NULL;
    }
    char *clientip = malloc(INET_ADDRSTRLEN);
    strcpy(clientip, inet_ntoa(addr.sin_addr));

    user_data->port = addr.sin_port;
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
    if (user_data->port) cJSON_AddNumberToObject(json, "src_port", user_data->port);
    if (user_data->containerID) cJSON_AddStringToObject(json, "container_id", user_data->containerID);
    if (user_data->username) cJSON_AddStringToObject(json, "username", user_data->username);
    if (user_data->password) cJSON_AddStringToObject(json, "password", user_data->password);
    char *json_str = cJSON_PrintUnformatted(json);

    FILE *fp = fopen("events.json", "a");
    if (fp == NULL) {
        printf("Error: Unable to open the file.\n");
        cJSON_free(json_str);
        cJSON_Delete(json);
        return 1;
    }
    printf("%s\n", json_str);
    fprintf(fp, "%s\n", json_str);
    fclose(fp);

    cJSON_free(json_str);
    cJSON_Delete(json);
    return 0;
}