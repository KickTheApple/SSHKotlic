//
// Created by domenic on 3/7/26.
//

#ifndef SSHKOTLIC_LOGGING_H
#define SSHKOTLIC_LOGGING_H

#include "main.h"

char* whatIsMyIP(int clientFD);
int userData_log(userData* user_data, char* event_type);

#endif //SSHKOTLIC_LOGGING_H