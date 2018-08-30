#include "proxy.h"
#include <lwip/init.h>
#include <lwip/netif.h>

struct proxy proxy_init()
{
    struct proxy proxy;
    if (!netif_add(&proxy.the_netif, &addr, &netmask, &gw, NULL, netif_init_func, netif_input_func)) {
        BLog(BLOG_ERROR, "netif_add failed");
        goto fail;
    }
}
