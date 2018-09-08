#ifndef _PROXY_H_
#define _PROXY_H_

#include <lwip/netif.h>

#define PROXY_BUFFER_SIZE 2000

typedef int (*send_packet_func_t)(void *userdata, const void *data, uint16_t len);
struct proxy {
    struct netif netif;
};
struct something {
    int (*init)();
    int (*accept)();
} fuck;

int proxy_init(struct proxy *proxy, send_packet_func_t send_packet, void *userdata);
void proxy_on_packet(struct proxy *proxy, const uint8_t *data, int data_len);

#endif // _PROXY_H_
