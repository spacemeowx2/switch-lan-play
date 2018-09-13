#include <lwip/netif.h>
#include "gateway.h"
#include "helper.h"
#include "packet.h"
#include "ipv4/ipv4.h"
#include <uv_lwip.h>
#include <base/llog.h>
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>
#include <lwip/ip4_frag.h>
#include <lwip/nd6.h>
#include <lwip/ip6_frag.h>

char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Organization: Nintendo\r\n\r\nok";

struct tcp_connection {
    struct tcp_pcb *pcb;
    uv_tcp_t socket;

    int proxy_up;
    int closed;

    const uint8_t *proxy_recv_buf;
    int proxy_recv_buf_used;
    int proxy_recv_buf_sent;
    int proxy_recv_tcp_pending;
};
typedef struct tcp_connection tcp_connection_t;

static struct packet_ctx *g_gateway_send_packet_ctx;

// lwip TCP listener
struct tcp_pcb *listener;

void gateway_on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
void client_free_client (tcp_connection_t *conn);

err_t netif_output_func (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    static uint8_t buffer[GATEWAY_BUFFER_SIZE];
    int ret;

    if (!p->next) {
        ret = lan_play_gateway_send_packet(g_gateway_send_packet_ctx, p->payload, p->len);
    } else {
        int len = 0;
        do {
            if (len + p->len > GATEWAY_BUFFER_SIZE) {
                return ERR_IF;
            }
            memcpy(buffer + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next));

        ret = lan_play_gateway_send_packet(g_gateway_send_packet_ctx, buffer, len);
    }

    if (ret != 0) {
        LLOG(LLOG_ERROR, "gateway_send_packet %d", ret);
    }

    return ret == 0 ? ERR_OK : ERR_IF;
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
        conn->proxy_recv_buf = (const uint8_t *)buf->base;
        conn->proxy_recv_buf_used = nread;

        // gateway_proxy_recv_send_out(conn);
    }
}

void gateway_on_connect(uv_connect_t *req, int status)
{
    tcp_connection_t *conn = req->handle->data;
    if (status < 0) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }

    LLOG(LLOG_DEBUG, "on_connect");

    conn->proxy_up = 1;
    conn->proxy_recv_buf = NULL;
    conn->proxy_recv_buf_used = 0;
    conn->proxy_recv_buf_sent = 0;
    conn->proxy_recv_tcp_pending = 0;

    uv_read_start(req->handle, gateway_on_alloc, gateway_on_read);
    free(req);
}

void gateway_event_thread(void *data)
{
    struct gateway *gateway = (struct gateway *)data;
    uv_loop_t *loop = gateway->loop;

    LLOG(LLOG_DEBUG, "uv_run");
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    LLOG(LLOG_DEBUG, "uv_loop_close");
}

void close_cb(uvl_tcp_t *client)
{
    puts("close_cb");
}

void write_cb(uvl_write_t *req, int status)
{
    puts("write_cb");

    assert(uvl_tcp_close(req->client, close_cb) == 0);

    free(req->data);
    free(req);
}

void read_cb(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    uvl_write_t *req = malloc(sizeof(uvl_write_t));
    uv_buf_t *b = malloc(sizeof(uv_buf_t));

    b->base = resp;
    b->len = strlen(resp);
    req->data = b;

    uvl_write(req, handle, b, 1, write_cb);
}

void alloc_cb(uvl_tcp_t *handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

void on_connect(uvl_t *handle, int status)
{
    assert(status == 0);

    uvl_tcp_t *client = malloc(sizeof(uvl_tcp_t));

    assert(uvl_tcp_init(handle->loop, client) == 0);
    assert(uvl_accept(handle, client) == 0);

    uvl_read_start(client, alloc_cb, read_cb);
    puts("accept, read start");
}

int gateway_uvl_output(uvl_t *handle, const uv_buf_t bufs[], unsigned int nbufs)
{
    uint8_t buffer[8192];
    uint8_t *buf = buffer;
    uint32_t len = 0;

    for (int i = 0; i < nbufs; i++) {
        memcpy(buf, bufs[i].base, bufs[i].len);
        buf += bufs[i].len;
        len += bufs[i].len;
    }

    return lan_play_gateway_send_packet(g_gateway_send_packet_ctx, buffer, len);
}

int gateway_init(struct gateway *gateway, struct packet_ctx *packet_ctx)
{
    g_gateway_send_packet_ctx = packet_ctx;

    // uv_loop_init(&gateway->loop);
    gateway->loop = packet_ctx->arg->loop;

    ASSERT(uvl_init(gateway->loop, &gateway->uvl) == 0);
    ASSERT(uvl_bind(&gateway->uvl, gateway_uvl_output) == 0);
    ASSERT(uvl_listen(&gateway->uvl, on_connect) == 0);
    gateway->uvl.data = gateway;

    proxy_direct_init(&gateway->proxy, gateway->loop, packet_ctx);
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
    // ignore ethernet part
    data += ETHER_OFF_END;
    data_len -= ETHER_OFF_END;

    if (gateway_process_udp(gateway, data, data_len) == 0) {
        return;
    }

    uv_buf_t b;

    b.base = (char *)data;
    b.len = data_len;

    uvl_input(&gateway->uvl, b);
}
