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

#if 0
#define malloc(size) ({ \
    void *__ptr = malloc(size); \
    LLOG(LLOG_DEBUG, "[malloc] %p %d", __ptr, __LINE__); \
    __ptr; \
})
#endif
typedef struct {
    uv_tcp_t dtcp;
    uvl_tcp_t stcp;
    int dclosed;
    int sclosed;
    int closing;

    uvl_write_t uvl_req;
    uv_buf_t uvl_buf;
    uv_write_t uv_req;
    uv_buf_t uv_buf;

    uint8_t buf1[65536];
    uint8_t buf2[65536];
} conn_t;
static struct packet_ctx *g_gateway_send_packet_ctx;

// lwip TCP listener
struct tcp_pcb *listener;

void gateway_on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
void close_cb(uvl_tcp_t *client);
void p_close_cb(uv_handle_t *handle);
static void conn_kill(conn_t *conn);
void p_write_cb(uv_write_t *req, int status);
void write_cb(uvl_write_t *req, int status);
void p_read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
void read_cb(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf);
void p_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf);
void alloc_cb(uvl_tcp_t *handle, size_t suggested_size, uv_buf_t* buf);

err_t netif_output_func (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    static uint8_t buffer[GATEWAY_BUFFER_SIZE];
    int ret;

    if (!p->next) {
        ret = lan_play_gateway_send_packet(g_gateway_send_packet_ctx, p->payload, p->len);
    } else {
        int len = 0;
        do {
            if (len + p->len > sizeof(buffer)) {
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

void conn_free(conn_t *conn)
{
    if (conn->sclosed && conn->dclosed) {
        LLOG(LLOG_DEBUG, "conn_kill %p done", conn);
        free(conn);
    }
}

void close_cb(uvl_tcp_t *client)
{
    puts("close_cb");
    conn_t *conn = client->data;
    conn->sclosed = 1;
    conn_free(conn);
}

void p_close_cb(uv_handle_t *handle)
{
    puts("p_close_cb");
    conn_t *conn = handle->data;
    conn->dclosed = 1;
    conn_free(conn);
}

static void conn_kill(conn_t *conn)
{
    assert(conn);
    if (conn->closing) {
        return;
    }
    conn->closing = 1;
    LLOG(LLOG_DEBUG, "conn_kill %p", conn);
    if (!conn->sclosed) {
        uvl_read_stop(&conn->stcp);
        uvl_tcp_close(&conn->stcp, close_cb);
    }
    if (!conn->dclosed) {
        uv_read_stop((uv_stream_t *)&conn->dtcp);
        uv_close((uv_handle_t *)&conn->dtcp, p_close_cb);
    }
}

void p_write_cb(uv_write_t *req, int status)
{
    conn_t *conn = req->data;
    if (status != 0) {
        printf("p_write_cb %d %s\n", status, uv_strerror(status));
    }

    // free(conn->uv_buf.base);

    assert(uvl_read_start(&conn->stcp, alloc_cb, read_cb) == 0);
}

void write_cb(uvl_write_t *req, int status)
{
    conn_t *conn = req->data;
    if (status) {
        printf("write_cb %d\n", status);
    }

    // free(conn->uvl_buf.base);

    int ret = uv_read_start((uv_stream_t *)&conn->dtcp, p_alloc_cb, p_read_cb);
    if (ret) {
        LLOG(LLOG_ERROR, "write_cb uv_read_start %d %s", ret, uv_strerror(ret));
    }
}

void p_read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    conn_t *conn = handle->data;
    if (nread <= 0) {
        LLOG(LLOG_DEBUG, "p_read_cb %d %s", nread, uv_strerror(nread));
        // free(buf->base);
        conn_kill(conn);
        return;
    }
    uv_read_stop(handle);

    uvl_write_t *req = &conn->uvl_req;

    conn->uvl_buf.base = buf->base;
    conn->uvl_buf.len = nread;

    uvl_write(req, &conn->stcp, &conn->uvl_buf, 1, write_cb);
}

void read_cb(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    conn_t *conn = handle->data;
    if (nread <= 0) {
        LLOG(LLOG_DEBUG, "read_cb %d", nread);
        // free(buf->base);
        conn_kill(conn);
        return;
    }
    uvl_read_stop(handle);

    uv_write_t *req = &conn->uv_req;

    conn->uv_buf.base = buf->base;
    conn->uv_buf.len = nread;

    uv_write(req, (uv_stream_t *)&conn->dtcp, &conn->uv_buf, 1, p_write_cb);
}

void p_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf)
{
    conn_t *conn = handle->data;
    buf->base = conn->buf1;
    buf->len = 65536;
}

void alloc_cb(uvl_tcp_t *handle, size_t suggested_size, uv_buf_t* buf)
{
    conn_t *conn = handle->data;
    buf->base = conn->buf2;
    buf->len = 65536;
}

static void p_on_connect(uv_connect_t *req, int status)
{
    conn_t *conn = req->data;
    if (status) {
        conn_kill(conn);
        free(req);
        return;
    }

    int ret;
    ret = uv_read_start((uv_stream_t *)&conn->dtcp, p_alloc_cb, p_read_cb);
    LLOG(LLOG_DEBUG, "p_on_connect %d", ret);

    free(req);
    assert(ret == 0);
    assert(uvl_read_start(&conn->stcp, alloc_cb, read_cb) == 0);
}

void on_connect(uvl_t *handle, int status)
{
    assert(status == 0);

    conn_t *conn = malloc(sizeof(conn_t));
    uv_connect_t *req = malloc(sizeof(uv_connect_t));
    uvl_tcp_t *client = &conn->stcp;
    int ret;

    conn->stcp.data = conn;
    conn->dtcp.data = conn;
    req->data = conn;
    conn->sclosed = 0;
    conn->dclosed = 0;
    conn->closing = 0;

    conn->uv_req.data = conn;
    conn->uvl_req.data = conn;

    assert(uvl_tcp_init(handle->loop, client) == 0);
    assert(uvl_accept(handle, client) == 0);

    assert(uv_tcp_init(handle->loop, &conn->dtcp) == 0);

    printf("%p accept, connect the other side ", client);
    PRINT_IP(&client->local_addr.sin_addr);
    printf(" %d ", ntohs(client->local_addr.sin_port));
    putchar('\n');
    ret = uv_tcp_connect(req, &conn->dtcp, (struct sockaddr *)&client->local_addr, p_on_connect);
    if (ret) {
        LLOG(LLOG_WARNING, "uv_tcp_connect failed %d %s", ret, uv_strerror(ret));
        free(req);
    }
}

int gateway_uvl_output(uvl_t *handle, const uv_buf_t bufs[], unsigned int nbufs)
{
    uint8_t buffer[8192];
    uint8_t *buf = buffer;
    uint32_t len = 0;

    for (int i = 0; i < nbufs; i++) {
        ASSERT(len + bufs[i].len < 8192)
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

    return 0;
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

        gateway->proxy.udp(&gateway->proxy, src, srcport, dst, dstport, payload, len);
        return 0;
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
