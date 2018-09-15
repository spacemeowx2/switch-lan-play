#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdint.h>
#include <uv.h>

#define PROXY_UDP_TABLE_LEN 128
#define PROXY_UDP_TABLE_TTL 30 // 30sec
struct proxy;
typedef struct proxy_tcp_s proxy_tcp_t;
typedef void (*proxy_connect_cb)(struct proxy *proxy, proxy_tcp_t *tcp);
struct proxy_udp_item {
    uint8_t src[4];
    uint16_t srcport;
    uv_udp_t *udp;
    struct proxy *proxy;
    time_t expire_at;
};
struct proxy {
    uv_loop_t *loop;
    struct packet_ctx *packet_ctx; // to send
    struct proxy_udp_item udp_table[PROXY_UDP_TABLE_LEN];

    int (*udp)(struct proxy *proxy, uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport, const void *data, uint16_t data_len);
    void (*close)(struct proxy *proxy);
    int *(*tcp_connect)();
};

int proxy_direct_init(struct proxy *proxy, uv_loop_t *loop, struct packet_ctx *packet_ctx);
int proxy_socks5_init();

#endif // _PROXY_H_
