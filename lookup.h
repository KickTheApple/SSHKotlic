//
// Created by domenic on 3/31/26.
//

#ifndef SSHKOTLIC_LOOKUP_H
#define SSHKOTLIC_LOOKUP_H

char* get_redis_entry(char* key);
int is_redis_entry(char* key);
int create_redis_entry(char* key, char* value);

#endif //SSHKOTLIC_LOOKUP_H