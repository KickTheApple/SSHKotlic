//
// Created by domenic on 3/31/26.
//

#ifndef SSHKOTLIC_CONCURRENT_H
#define SSHKOTLIC_CONCURRENT_H

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
void *pcap_thread(void* args);
void* read_thread(void* args);
void* write_thread(void* args);

#endif //SSHKOTLIC_CONCURRENT_H