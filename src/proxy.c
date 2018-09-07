#include "proxy.h"
#include "helper.h"
#include "packet.h"
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
    LLOG(LLOG_DEBUG, "netif_init_func %p", netif);
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = netif_output_func;
    // netif->output_ip6 = netif_output_ip6_func;

    return ERR_OK;
}


err_t listener_accept_func (void *arg, struct tcp_pcb *newpcb, err_t err)
{
    LLOG(LLOG_DEBUG, "listener_accept_func");
    return ERR_OK;
//     // allocate client structure
//     struct tcp_client *client = (struct tcp_client *)malloc(sizeof(*client));
//     if (!client) {
//         LLOG(LLOG_ERROR, "listener accept: malloc failed");
//         goto fail0;
//     }
//     client->socks_username = NULL;

//     SYNC_DECL
//     SYNC_FROMHERE

//     // read addresses
//     client->local_addr = baddr_from_lwip(&newpcb->local_ip, newpcb->local_port);
//     client->remote_addr = baddr_from_lwip(&newpcb->remote_ip, newpcb->remote_port);

//     // get destination address
//     BAddr addr = client->local_addr;
// #ifdef OVERRIDE_DEST_ADDR
//     ASSERT_FORCE(BAddr_Parse2(&addr, OVERRIDE_DEST_ADDR, NULL, 0, 1))
// #endif

//     // add source address to username if requested
//     if (options.username && options.append_source_to_username) {
//         char addr_str[BADDR_MAX_PRINT_LEN];
//         BAddr_Print(&client->remote_addr, addr_str);
//         client->socks_username = concat_strings(3, options.username, "@", addr_str);
//         if (!client->socks_username) {
//             goto fail1;
//         }
//         socks_auth_info[1].password.username = client->socks_username;
//         socks_auth_info[1].password.username_len = strlen(client->socks_username);
//     }

//     // init SOCKS
//     if (!BSocksClient_Init(&client->socks_client, socks_server_addr, socks_auth_info, socks_num_auth_info,
//                            addr, (BSocksClient_handler)client_socks_handler, client, &ss)) {
//         BLog(BLOG_ERROR, "listener accept: BSocksClient_Init failed");
//         goto fail1;
//     }

//     // init aborted and dead_aborted
//     client->aborted = 0;
//     DEAD_INIT(client->dead_aborted);

//     // add to linked list
//     LinkedList1_Append(&tcp_clients, &client->list_node);

//     // increment counter
//     ASSERT(num_clients >= 0)
//     num_clients++;

//     // set pcb
//     client->pcb = newpcb;

//     // set client not closed
//     client->client_closed = 0;

//     // setup handler argument
//     tcp_arg(client->pcb, client);

//     // setup handlers
//     tcp_err(client->pcb, client_err_func);
//     tcp_recv(client->pcb, client_recv_func);

//     // setup buffer
//     client->buf_used = 0;

//     // set SOCKS not up, not closed
//     client->socks_up = 0;
//     client->socks_closed = 0;

//     client_log(client, BLOG_INFO, "accepted");

//     DEAD_ENTER(client->dead_aborted)
//     SYNC_COMMIT
//     DEAD_LEAVE2(client->dead_aborted)

//     // Return ERR_ABRT if and only if tcp_abort was called from this callback.
//     return (DEAD_KILLED > 0) ? ERR_ABRT : ERR_OK;

// fail1:
//     SYNC_BREAK
//     free(client->socks_username);
//     free(client);
// fail0:
//     return ERR_MEM;
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
    // ip4_addr_set_any(&addr);
    // ip4_addr_set_any(&netmask);
    // ip4_addr_set_any(&gw);
    CPY_IPV4(&addr.addr, str2ip("10.13.37.1"));
    CPY_IPV4(&netmask.addr, str2ip("255.255.0.0"));
    ip4_addr_set_any(&gw);
    if (!netif_add(the_netif, &addr, &netmask, &gw, NULL, netif_init_func, netif_input_func)) {
        LLOG(LLOG_ERROR, "netif_add failed");
        exit(1);
    }
    LLOG(LLOG_DEBUG, "netif_list %p netif %p next %p", netif_list, the_netif, the_netif->next);

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

    // setup listener accept handler
    tcp_accept(listener, listener_accept_func);

    LLOG(LLOG_DEBUG, "proxy init netif_list %p", netif_list);

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
