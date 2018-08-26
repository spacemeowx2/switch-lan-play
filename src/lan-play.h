#ifndef _LAN_PLAY_H_
#define _LAN_PLAY_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>

struct lan_play;
#include "packet.h"
#include "helper.h"
#include "config.h"
#include "arp.h"

struct lan_play {
    pcap_t *dev;
    uint32_t id;
    void *buffer;
    uint8_t ip[4];
    uint8_t subnet_net[4];
    uint8_t subnet_mask[4];
    uint8_t mac[6];
    uint16_t identification;
    struct arp_item arp_list[ARP_CACHE_LEN];
    time_t arp_ttl;

    // forwarder
    int f_fd;
    int u_fd;
    pthread_mutex_t mutex;
    struct sockaddr_in server_addr;
};

void get_packet(struct lan_play *arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
int send_packet(struct lan_play *arg, int size);
int process_arp(struct lan_play *arg, const struct ether_frame *ether);
int process_ipv4(struct lan_play *arg, const struct ether_frame *ether);
void *forwarder_thread(void *);
void forwarder_init(struct lan_play *lan_play);
int forwarder_send(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

#endif // _LAN_PLAY_H_
