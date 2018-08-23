#ifndef _LAN_PLAY_H_
#define _LAN_PLAY_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

#include "packet.h"
#include "helper.h"
#include "config.h"

struct LanPlay {
    pcap_t *dev;
    uint32_t id;
    void *buffer;
    uint8_t mac[6];
    uint16_t identification;
};

void getPacket(struct LanPlay *arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
int processARP(struct LanPlay *arg, const u_char *packet);
int processIPv4(struct LanPlay *arg, const u_char *packet);
int sendPacket(struct LanPlay *arg, int size);

#endif // _LAN_PLAY_H_
