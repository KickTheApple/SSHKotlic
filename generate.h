//
// Created by domenic on 3/31/26.
//

#ifndef SSHKOTLIC_GENERATE_H
#define SSHKOTLIC_GENERATE_H

#include <wolfssh/ssh.h>

char* generate_session_id(int length);
int generate_socketFD();
int generate_SSH_Key(WOLFSSH_CTX*wolfssh_ctx, const char* name);

#endif //SSHKOTLIC_GENERATE_H