cmake_minimum_required(VERSION 4.0)
project(SSHKotlic C)

set(CMAKE_C_STANDARD 11)

add_executable(SSHKotlic main.c
        main.h
        logging.h
        logging.c
        callbacks.c
        callbacks.h)

target_link_directories(SSHKotlic PRIVATE /usr/local/lib)

target_link_libraries(SSHKotlic
        wolfssh
        wolfssl
        cjson
        hiredis
        pcap
)