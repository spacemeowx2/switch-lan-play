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
#include "rpc.h"
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
    char last_err[PCAP_ERRBUF_SIZE];
};

int lan_play_send_packet(struct lan_play *lan_play, void *data, int size);
int lan_play_gateway_send_packet(struct packet_ctx *packet_ctx, const void *data, uint16_t len);
int lan_client_init(struct lan_play *lan_play);
int lan_client_close(struct lan_play *lan_play);
int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

struct cli_options {
    int help;
    int version;

    bool broadcast;
    int pmtu;
    bool fake_internet;
    bool list_if;

    char *netif;
    char *netif_ipaddr;
    char *netif_netmask;

    char *socks5_server_addr;
    char *relay_server_addr;
    char *socks5_username;
    char *socks5_password;
    char *socks5_password_file;

    char *rpc;
    char *rpc_token;
    char *rpc_protocol;
};
extern struct cli_options options;
extern struct lan_play real_lan_play;
int lan_play_init(struct lan_play *lan_play);
int lan_play_close(struct lan_play *lan_play);

#define OPTIONS_DEC(name) void options_##name(const char *str);
#define OPTIONS_DEF(name) void options_##name(const char *str) \
{ \
    if (options.name) { \
        free(options.name); \
        options.name = NULL; \
    } \
    if (str && strlen(str)) { \
        options.name = strdup(str); \
    } \
}
OPTIONS_DEC(netif);
OPTIONS_DEC(socks5_server_addr);
OPTIONS_DEC(relay_server_addr);

#ifdef __cplusplus
}
#endif
#endif // _LAN_PLAY_H_
