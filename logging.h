//
// Created by domenic on 3/7/26.
//

#ifndef SSHKOTLIC_LOGGING_H
#define SSHKOTLIC_LOGGING_H

#include "main.h"

char* whatIsMyIP(int clientFD);
int secondContactLog(userData* user_data);
int firstContactLog(userData* user_data);

#endif //SSHKOTLIC_LOGGING_H