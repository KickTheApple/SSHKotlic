//
// Created by domenic on 3/7/26.
//

#ifndef SSHKOTLIC_CALLBACKS_H
#define SSHKOTLIC_CALLBACKS_H

#include <wolfssh/ssh.h>

int kotlic_ChannelCloseCallback(WOLFSSH_CHANNEL* channel, void* ctx);
int kotlic_ChannelEOFCallback(WOLFSSH_CHANNEL* channel, void* ctx);
int kotlic_ChannelOpenCallback(WOLFSSH_CHANNEL* channel, void* ctx);
int kotlic_ChannelRequestCallback(WOLFSSH_CHANNEL* channel, void* ctx);
int kotlic_UserAuthCallback(byte authType, WS_UserAuthData* authData, void* ctx);

#endif //SSHKOTLIC_CALLBACKS_H