//
// Created by domenic on 3/31/26.
//

#ifndef SSHKOTLIC_SHUTDOWN_H
#define SSHKOTLIC_SHUTDOWN_H

#include "main.h"

int kill_all_user_data(userData* billData);
void signal_catcher(int signal);
int shutdown_routine_yes_user(userData* bill_data);
int shutdown_routine_no_user();

#endif //SSHKOTLIC_SHUTDOWN_H