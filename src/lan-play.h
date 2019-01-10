#ifndef _LAN_PLAY_H_
#define _LAN_PLAY_H_

#include "config.h"

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
#include <base/debug.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lan_play;
#include "packet.h"
#include "helper.h"
#include "arp.h"
#include "gateway.h"
#include "pcaploop.h"

#ifndef LANPLAY_VERSION
#define LANPLAY_VERSION "unset"
#endif
#define CLIENT_RECV_BUF_LEN 4096

struct lan_client_fragment {
    uint16_t local_id;
    uint8_t src[4];
    uint16_t id;
    uint8_t part;
    uint8_t used;
    uint16_t total_len;
    uint8_t buffer[ETHER_MTU];
};

struct lan_play {
    pcap_t *dev;

    struct packet_ctx packet_ctx;

    uv_signal_t signal_int;
    uv_loop_t *loop;
    uv_pcap_t pcap;
    uint8_t client_buf[CLIENT_RECV_BUF_LEN];
    uv_udp_send_t client_send_req;

    // lan_client
    int pmtu;
    bool broadcast;
    bool next_real_broadcast;
    uv_udp_t client;
    uv_timer_t client_keepalive_timer;
    uv_timer_t real_broadcast_timer;
    int frag_id;
    int local_id;
    struct sockaddr_in server_addr;
    struct lan_client_fragment frags[LC_FRAG_COUNT];

    struct gateway *gateway;
};

int lan_play_send_packet(struct lan_play *lan_play, void *data, int size);
int lan_play_gateway_send_packet(struct packet_ctx *packet_ctx, const void *data, uint16_t len);
int lan_client_init(struct lan_play *lan_play);
int lan_client_close(struct lan_play *lan_play);
int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

#ifdef __cplusplus
}
#endif
#endif // _LAN_PLAY_H_
