#include "proxy.h"
#include "helper.h"
#include <base/llog.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>
#include <lwip/ip4_frag.h>
#include <lwip/nd6.h>
#include <lwip/ip6_frag.h>

static send_packet_func_t proxy_send_packet;
static void *proxy_send_userdata;

// lwip TCP listener
struct tcp_pcb *listener;

err_t netif_input_func(struct pbuf *p, struct netif *inp)
{
    uint8_t ip_version = 0;
    if (p->len > 0) {
        ip_version = (((uint8_t *)p->payload)[0] >> 4);
    }

    switch (ip_version) {
        case 4: {
            return ip4_input(p, inp);
        } break;
        case 6: {
            return ip6_input(p, inp);
        } break;
    }

    pbuf_free(p);
    return ERR_OK;
}

err_t netif_output_func (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    static uint8_t buffer[PROXY_BUFFER_SIZE];
    int ret;

    if (!p->next) {
        ret = proxy_send_packet(proxy_send_userdata, p->payload, p->len);
    } else {
        int len = 0;
        do {
            memcpy(buffer + len, p->payload, p->len);
            len += p->len;
        } while (p = p->next);

        ret = proxy_send_packet(proxy_send_userdata, buffer, len);
    }

    if (ret != 0) {
        LLOG(LLOG_ERROR, "proxy_send_packet %d", ret);
    }

    return ret == 0 ? ERR_OK : ERR_IF;
}

err_t netif_init_func (struct netif *netif)
{
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = netif_output_func;
    // netif->output_ip6 = netif_output_ip6_func;

    return ERR_OK;
}

void addr_from_lwip(void *ip, const ip_addr_t *ip_addr)
{
    if (IP_IS_V6(ip_addr)) {
        LLOG(LLOG_ERROR, "ipv6 not support now");
        return;
    } else {
        CPY_IPV4(ip, &ip_addr->u_addr.ip4.addr);
    }
}

void on_connect(uv_connect_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }

    LLOG(LLOG_DEBUG, "on_connect");
    free(req);
}

err_t listener_accept_func (void *arg, struct tcp_pcb *newpcb, err_t err)
{
    struct proxy *proxy = arg;
    uv_loop_t *loop = &proxy->loop;
    uint8_t local_addr[4];
    uint8_t remote_addr[4];
    struct sockaddr_in dest;

    addr_from_lwip(local_addr, &newpcb->local_ip);
    addr_from_lwip(remote_addr, &newpcb->remote_ip);

    LLOG(LLOG_DEBUG, "listener_accept_func");
    PRINT_IP(local_addr);
    printf(":%d <- ", newpcb->local_port);
    PRINT_IP(remote_addr);
    printf(":%d\n", newpcb->remote_port);

    dest.sin_family = AF_INET;
    dest.sin_addr = *((struct in_addr *)local_addr);
    dest.sin_port = htons(newpcb->local_port);

    uv_tcp_t* socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    uv_tcp_init(loop, socket);

    uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);

    return ERR_OK;
}

void *proxy_event_thread(void *data)
{
    struct proxy *proxy = (struct proxy *)data;

    LLOG(LLOG_DEBUG, "uv_run");
    uv_run(&proxy->loop, UV_RUN_DEFAULT);
    uv_loop_close(&proxy->loop);
    LLOG(LLOG_DEBUG, "uv_loop_close");

    return NULL;
}

int proxy_init(struct proxy *proxy, send_packet_func_t send_packet, void *userdata)
{
    struct netif *the_netif = &proxy->netif;
    proxy_send_userdata = userdata;
    proxy_send_packet = send_packet;
    lwip_init();

    // make addresses for netif
    ip4_addr_t addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    ip4_addr_set_any(&addr);
    ip4_addr_set_any(&netmask);
    ip4_addr_set_any(&gw);
    // CPY_IPV4(&addr.addr, str2ip("10.13.37.1"));
    // CPY_IPV4(&netmask.addr, str2ip("255.255.0.0"));
    // ip4_addr_set_any(&gw);
    if (!netif_add(the_netif, &addr, &netmask, &gw, NULL, netif_init_func, netif_input_func)) {
        LLOG(LLOG_ERROR, "netif_add failed");
        exit(1);
    }

    // set netif up
    netif_set_up(the_netif);

    // set netif link up, otherwise ip route will refuse to route
    netif_set_link_up(the_netif);

    // set netif pretend TCP
    netif_set_pretend_tcp(the_netif, 1);

    // set netif default
    netif_set_default(the_netif);

    // init listener
    struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!l) {
        LLOG(LLOG_ERROR, "tcp_new_ip_type failed");
        goto fail;
    }

    // bind listener
    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
        LLOG(LLOG_ERROR, "tcp_bind_to_netif failed");
        tcp_close(l);
        goto fail;
    }

    // ensure the listener only accepts connections from this netif
    // tcp_bind_netif(l, the_netif);

    // listen listener
    if (!(listener = tcp_listen(l))) {
        LLOG(LLOG_ERROR, "tcp_listen failed");
        tcp_close(l);
        goto fail;
    }

    tcp_arg(listener, proxy);
    // setup listener accept handler
    tcp_accept(listener, listener_accept_func);

    LLOG(LLOG_DEBUG, "proxy init netif_list %p", netif_list);

    uv_loop_init(&proxy->loop);
    pthread_create(&proxy->loop_thread, NULL, proxy_event_thread, &proxy);

    return 0;
fail:
    exit(1);
}

void proxy_on_packet(struct proxy *proxy, const uint8_t *data, int data_len)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, data_len, PBUF_POOL);

    if (!p) {
        LLOG(LLOG_WARNING, "device read: pbuf_alloc failed");
        return;
    }

    if (pbuf_take(p, data + 14, data_len - 14) != ERR_OK) {
        LLOG(LLOG_ERROR, "pbuf_take");
        exit(1);
    }

    if (proxy->netif.input(p, &proxy->netif) != ERR_OK) {
        LLOG(LLOG_WARNING, "device read: input failed");
        pbuf_free(p);
    }
}
