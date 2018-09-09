#include "gateway.h"
#include "helper.h"
#include "packet.h"
#include "ipv4/ipv4.h"
#include <base/llog.h>
#include <math.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>
#include <lwip/ip4_frag.h>
#include <lwip/nd6.h>
#include <lwip/ip6_frag.h>

// #define ASSERT(x) { if (!x) { LLOG(LLOG_ERROR, "fatal: assert '%s' failed", #x); exit(1);} }
struct tcp_connection {
    struct tcp_pcb *pcb;
    uv_tcp_t socket;
    int closed;

    uint8_t *proxy_recv_buf;
    int proxy_recv_buf_used;
    int proxy_recv_buf_sent;
    int proxy_recv_tcp_pending;
};
typedef struct tcp_connection tcp_connection_t;

static struct packet_ctx *g_gateway_send_packet_ctx;

// lwip TCP listener
struct tcp_pcb *listener;

void gateway_on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
void client_free_client (tcp_connection_t *connection);

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
    static uint8_t buffer[GATEWAY_BUFFER_SIZE];
    int ret;

    if (!p->next) {
        ret = lan_play_gateway_send_packet(g_gateway_send_packet_ctx, p->payload, p->len);
    } else {
        int len = 0;
        do {
            memcpy(buffer + len, p->payload, p->len);
            len += p->len;
        } while (p = p->next);

        ret = lan_play_gateway_send_packet(g_gateway_send_packet_ctx, buffer, len);
    }

    if (ret != 0) {
        LLOG(LLOG_ERROR, "gateway_send_packet %d", ret);
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

void gateway_on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    LLOG(LLOG_DEBUG, "gateway_on_alloc %p %d", handle, suggested_size);
}

void gateway_write_cb(uv_write_t* req, int status)
{
    if (status < 0) {
        LLOG(LLOG_ERROR, "gateway_write_cb %d", status);
    }
    free(req->data);
    free(req);
}

int gateway_proxy_recv_send_out(tcp_connection_t *conn)
{
    ASSERT(conn->proxy_recv_buf)
    ASSERT(!conn->closed)
    ASSERT(conn->proxy_recv_buf_used > 0)
    ASSERT(conn->proxy_recv_buf_sent < conn->proxy_recv_buf_used)

    struct tcp_pcb *pcb = conn->pcb;
    int sndbuf = tcp_sndbuf(pcb);

    err_t err;
    do {
        int to_write = min(sndbuf, conn->proxy_recv_buf_used - conn->proxy_recv_buf_sent);
        err = tcp_write(pcb, conn->proxy_recv_buf + conn->proxy_recv_buf_sent, to_write, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            if (err == ERR_MEM) {
                break;
            }
            LLOG(LLOG_ERROR, "gateway_on_read tcp_write %d", err);
            return -1;
        }
        conn->proxy_recv_buf_sent += to_write;
        conn->proxy_recv_tcp_pending += to_write;
    } while (conn->proxy_recv_buf_sent < conn->proxy_recv_buf_used);

    err = tcp_output(pcb);
    if (err != ERR_OK) {
        LLOG(LLOG_ERROR, "gateway_on_read tcp_output %d", err);
        return -1;
    }

    if (conn->proxy_recv_buf_sent == conn->proxy_recv_buf_used) {
        conn->proxy_recv_buf_used = 0;
    }

    return 0;
}

err_t client_sent_func (void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    tcp_connection_t *conn = arg;
    uv_tcp_t* socket = &conn->socket;

    ASSERT(!conn->closed)
    // ASSERT(conn->socks_up)
    ASSERT(len > 0)
    ASSERT(len <= conn->proxy_recv_tcp_pending)

    conn->proxy_recv_tcp_pending -= len;
    if (conn->proxy_recv_buf_used > 0) {
        ASSERT(conn->proxy_recv_buf_sent < conn->proxy_recv_buf_used)

        int ret = gateway_proxy_recv_send_out(conn);
    } else if (conn->proxy_recv_tcp_pending == 0) {
        conn->proxy_recv_buf = NULL;
        conn->proxy_recv_buf_used = 0;
        conn->proxy_recv_buf_sent = 0;
        uv_read_start((uv_stream_t *)&conn->socket, gateway_on_alloc, gateway_on_read);
        LLOG(LLOG_DEBUG, "read restart");
    }
}

void gateway_on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    tcp_connection_t *conn = (tcp_connection_t *)handle->data;
    ASSERT(conn->proxy_recv_buf == NULL)
    ASSERT(!conn->closed)
    ASSERT(conn->proxy_recv_buf_used == 0)
    ASSERT(conn->proxy_recv_buf_sent == 0)

    uv_read_stop(handle);
    LLOG(LLOG_DEBUG, "read stop");

    LLOG(LLOG_DEBUG, "gateway_on_read %d", nread);
    LLOG(LLOG_DEBUG, "conn %p", handle->data);

    if (nread <= 0) {
        // client_free_client(conn);
    } else {
        conn->proxy_recv_buf = buf->base;
        conn->proxy_recv_buf_used = nread;

        gateway_proxy_recv_send_out(conn);
    }
}

void gateway_on_connect(uv_connect_t *req, int status)
{
    if (status < 0) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }

    LLOG(LLOG_DEBUG, "on_connect");

    tcp_connection_t *conn = req->handle->data;
    conn->proxy_recv_buf = NULL;
    conn->proxy_recv_buf_used = 0;
    conn->proxy_recv_buf_sent = 0;
    conn->proxy_recv_tcp_pending = 0;

    uv_read_start(req->handle, gateway_on_alloc, gateway_on_read);
    free(req);
}

void client_free_client (tcp_connection_t *conn)
{
    ASSERT(!conn->closed)

    // remove callbacks
    tcp_err(conn->pcb, NULL);
    tcp_recv(conn->pcb, NULL);
    tcp_sent(conn->pcb, NULL);

    // free pcb
    err_t err = tcp_close(conn->pcb);
    if (err != ERR_OK) {
        LLOG(LLOG_ERROR, "tcp_close failed (%d)", err);
        tcp_abort(conn->pcb);
    }

    // stop_uv
    int ret = uv_read_stop(&conn->socket);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_read_stop (%d)", ret);
    }
}

err_t client_recv_func (void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    tcp_connection_t *connection = arg;
    uv_tcp_t* socket = &connection->socket;
    uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
    uint8_t *buff = malloc(2048);

    if (p) {
        uv_buf_t buf;
        buf.base = buff;
        buf.len = p->tot_len;

        LLOG(LLOG_DEBUG, "client_recv_func %d", p->tot_len);
        pbuf_copy_partial(p, buff, p->tot_len, 0);
        req->data = buff;

        uv_write(req, (uv_stream_t *)socket, &buf, 1, gateway_write_cb);
    } else {
        LLOG(LLOG_INFO, "client closed");
        client_free_client(connection);
    }
}

void client_err_func (void *arg, err_t err)
{
    tcp_connection_t *connection = arg;

    LLOG(LLOG_INFO, "client err %d", (int)err);
}

err_t listener_accept_func (void *arg, struct tcp_pcb *newpcb, err_t err)
{
    struct gateway *gateway = arg;
    uv_loop_t *loop = &gateway->loop;
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

    tcp_connection_t *connection = (tcp_connection_t *)malloc(sizeof(tcp_connection_t));
    uv_tcp_t* socket = &connection->socket;
    uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    uv_tcp_init(loop, socket);

    connection->closed = 0;
    connection->pcb = newpcb;
    socket->data = connection;
    tcp_arg(newpcb, connection);
    LLOG(LLOG_DEBUG, "socket->data %p", connection);

    tcp_err(newpcb, client_err_func);
    tcp_recv(newpcb, client_recv_func);
    tcp_sent(newpcb, client_sent_func);

    uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, gateway_on_connect);

    return ERR_OK;
}

void gateway_on_timer(uv_timer_t *timer)
{
    struct gateway *gateway = (struct gateway *)timer->data;
    tcp_tmr();
}

void gateway_event_thread(void *data)
{
    struct gateway *gateway = (struct gateway *)data;
    uv_loop_t *loop = &gateway->loop;
    uv_timer_t timer;

    uv_timer_init(loop, &timer);
    timer.data = gateway;
    uv_timer_start(&timer, gateway_on_timer, 0, 250);
    LLOG(LLOG_DEBUG, "uv_run");
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    LLOG(LLOG_DEBUG, "uv_loop_close");
}

int gateway_send_udp()
{

}

int gateway_init(struct gateway *gateway, struct packet_ctx *packet_ctx)
{
    struct netif *the_netif = &gateway->netif;
    g_gateway_send_packet_ctx = packet_ctx;
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

    tcp_arg(listener, gateway);
    // setup listener accept handler
    tcp_accept(listener, listener_accept_func);

    LLOG(LLOG_DEBUG, "gateway init netif_list %p", netif_list);

    uv_loop_init(&gateway->loop);
    proxy_direct_init(&gateway->proxy, &gateway->loop, packet_ctx);
    uv_thread_create(&gateway->loop_thread, gateway_event_thread, gateway);

    return 0;
fail:
    exit(1);
}

int gateway_process_udp(struct gateway *gateway, const uint8_t *data, int data_len)
{
    uint8_t ip_version = 0;
    if (data_len > 0) {
        ip_version = (data[0] >> 4);
    }

    if (ip_version == 4) {
        // ignore non-UDP packets
        if (data_len < IPV4_OFF_END || data[IPV4_OFF_PROTOCOL] != IPV4_PROTOCOL_UDP) {
            return -1;
        }
        uint16_t ipv4_header_len = (data[0] & 0xF) * 4;
        const uint8_t *udp_base = data + ipv4_header_len;
        uint8_t src[4];
        uint8_t dst[4];
        uint16_t srcport;
        uint16_t dstport;
        const void *payload;
        uint16_t len;

        CPY_IPV4(src, data + IPV4_OFF_SRC);
        CPY_IPV4(dst, data + IPV4_OFF_DST);
        srcport = READ_NET16(udp_base, UDP_OFF_SRCPORT);
        dstport = READ_NET16(udp_base, UDP_OFF_DSTPORT);
        payload = udp_base + UDP_OFF_END;
        len = data_len - ipv4_header_len - UDP_OFF_END;

        // PRINT_IP(src);
        // printf(":%d -> ", srcport);
        // PRINT_IP(dst);
        // printf(":%d\n", dstport);

        return gateway->proxy.udp(&gateway->proxy, src, srcport, dst, dstport, payload, len);;
    }

    return -1;
}

void gateway_on_packet(struct gateway *gateway, const uint8_t *data, int data_len)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, data_len, PBUF_POOL);

    // ignore ethernet part
    data += ETHER_OFF_END;
    data_len -= ETHER_OFF_END;

    if (!p) {
        LLOG(LLOG_WARNING, "device read: pbuf_alloc failed");
        return;
    }

    if (gateway_process_udp(gateway, data, data_len) == 0) {
        return;
    }

    if (pbuf_take(p, data, data_len) != ERR_OK) {
        LLOG(LLOG_ERROR, "pbuf_take");
        exit(1);
    }

    if (gateway->netif.input(p, &gateway->netif) != ERR_OK) {
        LLOG(LLOG_WARNING, "device read: input failed");
        pbuf_free(p);
    }
}
