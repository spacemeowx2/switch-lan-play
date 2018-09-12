#ifndef _LAN_PLAY_H_
#define _LAN_PLAY_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <base/llog.h>
#include <uv.h>

struct lan_play;
#include "packet.h"
#include "helper.h"
#include "config.h"
#include "arp.h"
#include "gateway.h"
#include "proxy.h"

struct lan_play {
    pcap_t *dev;

    struct packet_ctx packet_ctx;

    bool stop;
    uv_loop_t *loop;
    uv_thread_t libpcap_thread;
    uv_async_t get_packet_async;
    uv_sem_t get_packet_sem;
    const struct pcap_pkthdr *pkthdr;
    const u_char *packet;

    // lan_client
    uv_udp_t client;
    uv_timer_t client_keepalive_timer;
    uv_buf_t client_send_buf[2];
    struct sockaddr_in server_addr;

    struct gateway gateway;
    uv_loop_t real_loop;
};

int lan_play_send_packet(struct lan_play *lan_play, void *data, int size);
int lan_play_gateway_send_packet(struct packet_ctx *packet_ctx, const void *data, uint16_t len);
int lan_client_init(struct lan_play *lan_play);
int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

#endif // _LAN_PLAY_H_
