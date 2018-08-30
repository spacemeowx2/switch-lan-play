#ifndef _PROXY_H_
#define _PROXY_H_

struct proxy {
    struct netif netif;
};

struct proxy proxy_init();
int proxy_on_packet();

#endif // _PROXY_H_
