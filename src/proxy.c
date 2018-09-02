#include "proxy.h"
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/ip.h>

err_t netif_input_func (struct pbuf *p, struct netif *inp)
{
    uint8_t ip_version = 0;
    if (p->len > 0) {
        ip_version = (((uint8_t *)p->payload)[0] >> 4);
    }

    switch (ip_version) {
        case 4: {
            return ip_input(p, inp);
        } break;
        case 6: {
            return ip6_input(p, inp);
        } break;
    }

    pbuf_free(p);
    return ERR_OK;
}

err_t netif_init_func (struct netif *netif)
{
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    // netif->output = netif_output_func;
    // netif->output_ip6 = netif_output_ip6_func;

    return ERR_OK;
}

struct proxy proxy_init()
{
    struct proxy proxy;
    lwip_init();

    // make addresses for netif
    ip4_addr_t addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    ip4_addr_set_any(&addr);
    ip4_addr_set_any(&netmask);
    ip4_addr_set_any(&gw);
    if (!netif_add(&proxy.netif, &addr, &netmask, &gw, NULL, netif_init_func, netif_input_func)) {
        fprintf(stderr, "netif_add failed");
        exit(1);
    }
    return proxy;
}
