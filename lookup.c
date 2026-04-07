//
// Created by domenic on 3/31/26.
//


#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>

#include "lookup.h"
#include "main.h"

extern serverData server_data;

char* get_redis_entry(char* key) {
    char* redis_value = malloc(65);

    redisReply* reply = redisCommand(server_data.redisConn, "get %s", key);
    printf("%s\n", key);
    if (reply == NULL) {
        printf("Redis Reply couldn't have been created\n");
        free(redis_value);
        return NULL;
    }
    if (reply->str == NULL) {
        printf("Redis entry not found\n");
        freeReplyObject(reply);
        free(redis_value);
        return NULL;
    }
    printf("%s\n", reply->str);
    memcpy(redis_value, reply->str, reply->len < 64 ? reply->len : 64);
    redis_value[reply->len < 64 ? reply->len : 64] = '\0';

    freeReplyObject(reply);
    printf("Redis entry successfully found\n");
    return redis_value;
}

int is_redis_entry(char* key) {
    printf("DO WE GET HERE\n");
    redisReply* reply = redisCommand(server_data.redisConn, "get %s", key);
    printf("%s\n", key);
    if (reply == NULL) {
        printf("WE DO DO NOT HAVE\n");
        return -1;
    }
    if (reply->str == NULL) {
        printf("We did not find value\n");
        freeReplyObject(reply);
        return 0;
    }
    printf("%s\n", reply->str);
    freeReplyObject(reply);
    printf("WE DO GET HERE\n");
    return 1;
}

int create_redis_entry(char* key, char* value) {
    redisReply* reply = redisCommand(server_data.redisConn, "set %s %s", key, value);
    if (strcmp(reply->str, "OK") == 0) {
        freeReplyObject(reply);
        return 1;
    }
    freeReplyObject(reply);
    return 0;
}