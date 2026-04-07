//
// Created by domenic on 3/7/26.
//

#ifndef SSHKOTLIC_LOGGING_H
#define SSHKOTLIC_LOGGING_H

#include <curl/curl.h>

#include "main.h"

int pcap_sender(userData* user_data);
char* whatIsMyIP(int clientFD, userData* user_data);
int bashinput_log(byte* data, userData* user_data);
int userData_log(userData* user_data, char* event_type);

#endif //SSHKOTLIC_LOGGING_H