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

#define CONN_BUF_SIZE 65536

typedef struct conn_s {
    uv_tcp_t ptcp;
    uvl_tcp_t stcp;
    int pconnected;
    int pclosed;
    int sclosed;
    int closing;
    uvl_write_t uvl_req;
    uv_write_t uv_req;

    union {
        uv_connect_t req;
        struct {
            uv_buf_t uvl_buf;
            uv_buf_t uv_buf;

            uint8_t buf1[CONN_BUF_SIZE];
            uint8_t buf2[CONN_BUF_SIZE];
        } s;
    } u;

    struct gateway *gateway;
    conn_t *next;
} conn_t;

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
    if (conn->sclosed && conn->pclosed) {

        conn_t **pcur = &conn->gateway->first_conn;

        while (*pcur) {
            if (*pcur == conn) {
                *pcur = conn->next;
                break;
            }
            pcur = &(*pcur)->next;
        }

        free(conn);
    }
}

void close_cb(uvl_tcp_t *client)
{
    conn_t *conn = client->data;
    conn->sclosed = 1;
    conn_free(conn);
}

void p_close_cb(uv_handle_t *handle)
{
    conn_t *conn = handle->data;
    conn->pclosed = 1;
    conn_free(conn);
}

static void conn_kill(conn_t *conn)
{
    assert(conn);
    if (conn->closing) {
        return;
    }
    conn->closing = 1;

    if (!conn->pconnected) {
        uv_cancel((uv_req_t *)&conn->u.req);
    }
    if (!conn->sclosed) {
        uvl_read_stop(&conn->stcp);
        uvl_tcp_close(&conn->stcp, close_cb);
    }
    if (!conn->pclosed) {
        uv_read_stop((uv_stream_t *)&conn->ptcp);
        uv_close((uv_handle_t *)&conn->ptcp, p_close_cb);
    }
}

void p_write_cb(uv_write_t *req, int status)
{
    conn_t *conn = req->data;
    if (status != 0) {
        LLOG(LLOG_DEBUG, "p_write_cb %d %s\n", status, uv_strerror(status));
    }

    RT_ASSERT(uvl_read_start(&conn->stcp, alloc_cb, read_cb) == 0);
}

void write_cb(uvl_write_t *req, int status)
{
    conn_t *conn = req->data;
    if (status) {
        LLOG(LLOG_DEBUG, "write_cb %d\n", status);
    }

    int ret = uv_read_start((uv_stream_t *)&conn->ptcp, p_alloc_cb, p_read_cb);
    if (ret) {
        LLOG(LLOG_ERROR, "write_cb uv_read_start %d %s", ret, uv_strerror(ret));
    }
}

void p_read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    conn_t *conn = handle->data;
    if (nread <= 0) {
        LLOG(LLOG_DEBUG, "p_read_cb %d %s", nread, uv_strerror(nread));
        conn_kill(conn);
        return;
    }
    uv_read_stop(handle);

    uvl_write_t *req = &conn->uvl_req;

    conn->u.s.uvl_buf.base = buf->base;
    conn->u.s.uvl_buf.len = nread;

    uvl_write(req, &conn->stcp, &conn->u.s.uvl_buf, 1, write_cb);
}

void read_cb(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    conn_t *conn = handle->data;
    if (nread <= 0) {
        LLOG(LLOG_DEBUG, "read_cb %d", nread);
        conn_kill(conn);
        return;
    }
    uvl_read_stop(handle);

    uv_write_t *req = &conn->uv_req;

    conn->u.s.uv_buf.base = buf->base;
    conn->u.s.uv_buf.len = nread;

    uv_write(req, (uv_stream_t *)&conn->ptcp, &conn->u.s.uv_buf, 1, p_write_cb);
}

void p_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf)
{
    conn_t *conn = handle->data;
    *buf = uv_buf_init((char *)conn->u.s.buf1, sizeof(conn->u.s.buf1));
}

void alloc_cb(uvl_tcp_t *handle, size_t suggested_size, uv_buf_t* buf)
{
    conn_t *conn = handle->data;
    *buf = uv_buf_init((char *)conn->u.s.buf2, sizeof(conn->u.s.buf2));
}

static void p_on_connect(uv_connect_t *req, int status)
{
    conn_t *conn = req->data;
    conn->pconnected = 1;
    if (status) {
        conn_kill(conn);
        return;
    }

    int ret;
    conn->pclosed = 0;
    ret = uv_read_start((uv_stream_t *)&conn->ptcp, p_alloc_cb, p_read_cb);

    if (ret) {
        LLOG(LLOG_ERROR, "p_on_connect %d", ret);
    }

    RT_ASSERT(ret == 0);
    RT_ASSERT(uvl_read_start(&conn->stcp, alloc_cb, read_cb) == 0);
}

void fake_close_cb(uvl_tcp_t *client)
{
    free(client->data);
}

void fake_write_cb(uvl_write_t *req, int status)
{
    uvl_tcp_close(req->client, fake_close_cb);
}

void on_fake_connect(uvl_t *handle, int status)
{
    assert(status == 0);

    struct gateway *gateway = (struct gateway *)handle->data;
    struct {
        uvl_tcp_t client;
        uvl_write_t req;
        uv_buf_t buf;
    } *fake = malloc(sizeof(*fake));
    fake->client.data = fake;
    char *fake_body = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Organization: Nintendo\r\n\r\nok";
    fake->buf = uv_buf_init(fake_body, strlen(fake_body));

    RT_ASSERT(uvl_tcp_init(gateway->loop, &fake->client) == 0);
    RT_ASSERT(uvl_accept(handle, &fake->client) == 0);

    RT_ASSERT(uvl_write(&fake->req, &fake->client, &fake->buf, 1, fake_write_cb) == 0);
}

void on_connect(uvl_t *handle, int status)
{
    assert(status == 0);

    struct gateway *gateway = (struct gateway *)handle->data;
    conn_t *conn = malloc(sizeof(conn_t));
    uv_connect_t *req = &conn->u.req;
    uvl_tcp_t *client = &conn->stcp;
    int ret;

    conn->gateway = gateway;
    conn->next = gateway->first_conn;
    gateway->first_conn = conn;

    conn->stcp.data = conn;
    conn->ptcp.data = conn;
    req->data = conn;

    conn->pconnected = 0;
    conn->sclosed = 0;
    conn->pclosed = 0;
    conn->closing = 0;

    conn->uv_req.data = conn;
    conn->uvl_req.data = conn;

    RT_ASSERT(uvl_tcp_init(gateway->loop, client) == 0);
    RT_ASSERT(uvl_accept(handle, client) == 0);

    RT_ASSERT(uv_tcp_init(gateway->loop, &conn->ptcp) == 0);

    printf("%p accept, connect ", client);
    PRINT_IP(&client->local_addr.sin_addr);
    printf(":%d", ntohs(client->local_addr.sin_port));
    putchar('\n');
    ret = uv_tcp_connect(req, &conn->ptcp, (struct sockaddr *)&client->local_addr, p_on_connect);
    if (ret) {
        LLOG(LLOG_WARNING, "uv_tcp_connect failed %d %s", ret, uv_strerror(ret));
    }
}

int gateway_uvl_output(uvl_t *handle, const uv_buf_t bufs[], unsigned int nbufs)
{
    struct gateway *gateway = (struct gateway *)handle->data;
    uint8_t buffer[8192];
    uint8_t *buf = buffer;
    uint32_t len = 0;
    int i;

    for (i = 0; i < nbufs; i++) {
        RT_ASSERT(len + bufs[i].len < sizeof(buffer))
        memcpy(buf, bufs[i].base, bufs[i].len);
        buf += bufs[i].len;
        len += bufs[i].len;
    }

    return lan_play_gateway_send_packet(gateway->packet_ctx, buffer, len);
}

int gateway_init(struct gateway *gateway, struct packet_ctx *packet_ctx, bool fake_internet)
{
    gateway->loop = packet_ctx->arg->loop;
    gateway->packet_ctx = packet_ctx;

    RT_ASSERT(uvl_init(gateway->loop, &gateway->uvl) == 0);
    RT_ASSERT(uvl_bind(&gateway->uvl, gateway_uvl_output) == 0);
    if (fake_internet) {
        RT_ASSERT(uvl_listen(&gateway->uvl, on_fake_connect) == 0);
    } else {
        RT_ASSERT(uvl_listen(&gateway->uvl, on_connect) == 0);
    }
    gateway->uvl.data = gateway;
    gateway->first_conn = NULL;

    proxy_direct_init(&gateway->proxy, gateway->loop, packet_ctx);

    return 0;
}

int gateway_close(struct gateway *gateway)
{
    gateway->proxy.close(&gateway->proxy);

    uvl_close(&gateway->uvl, NULL);

    conn_t *cur = gateway->first_conn;
    conn_t *next;

    while (cur) {
        next = cur->next;
        conn_kill(cur);
        cur = next;
    }
    gateway->first_conn = NULL;

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
