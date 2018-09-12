#include "proxy.h"
#include "helper.h"
#include "gateway.h"
#include "packet.h"
#include "ipv4/ipv4.h"
#include <assert.h>
#include <base/llog.h>

static void proxy_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    // LLOG(LLOG_DEBUG, "proxy_alloc_cb %p %d %p", handle, suggested_size, buf->base);
}

void proxy_udp_send_cb(uv_udp_send_t *req, int status)
{
    if (status < 0) {
        LLOG(LLOG_ERROR, "proxy_udp_send_cb %d", status);
    }
    free(req);
}

void proxy_udp_recv_cb(uv_udp_t *udp, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
    if (nread <= 0) {
        LLOG(LLOG_DEBUG, "proxy_udp_recv_cb nread: %d", nread);
        return;
    }

    struct proxy_udp_item *item = (struct proxy_udp_item *)udp->data;
    struct payload part;
    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
    const void *from_ip = &addr_in->sin_addr;
    uint16_t from_port = ntohs(addr_in->sin_port);

    part.ptr = (const u_char *)buf->base;
    part.len = nread;
    part.next = NULL;

    int ret = send_udp_ex(item->proxy->packet_ctx, from_ip, from_port, item->src, item->srcport, &part);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "proxy_udp_recv_cb %d", ret);
    }
    free(buf->base);
}

// Get or add in the table, return NULL if failed
uv_udp_t *proxy_udp_get(struct proxy *proxy, uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport)
{
    struct proxy_udp_item *items = proxy->udp_table;
    time_t now = time(NULL);
    int i;

    for (i = 0; i < PROXY_UDP_TABLE_LEN; i++) {
        struct proxy_udp_item *item = &items[i];
        if (
            (item->udp != NULL)
            && (item->expire_at >= now)
            && CMP_IPV4(item->src, src)
            && item->srcport == srcport
        ) {
            item->expire_at = now + PROXY_UDP_TABLE_TTL;
            return item->udp;
        }
    }

    // didn't find
    for (i = 0; i < PROXY_UDP_TABLE_LEN; i++) {
        struct proxy_udp_item *item = &items[i];
        if (
            (item->udp == NULL) || (item->expire_at < now)
        ) {
            item->udp = (uv_udp_t *)malloc(sizeof(uv_udp_t));
            item->expire_at = now + PROXY_UDP_TABLE_TTL;
            item->proxy = proxy;

            uv_udp_init(proxy->loop, item->udp);
            uv_udp_recv_start(item->udp, proxy_alloc_cb, proxy_udp_recv_cb);
            item->udp->data = item;

            CPY_IPV4(item->src, src);
            item->srcport = srcport;

            return item->udp;
        }
    }

    return NULL;
}

int proxy_direct_udp(struct proxy *proxy, uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport, const void *data, uint16_t data_len)
{
    uv_loop_t *loop = proxy->loop;

    uv_udp_t *udp = proxy_udp_get(proxy, src, srcport, dst, dstport);
    if (udp == NULL) {
        LLOG(LLOG_WARNING, "proxy_udp_get failed");
        return -1;
    }

    uv_udp_send_t *req = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));
    uv_buf_t buf;
    struct sockaddr_in addr;

    buf.base = (char *)data;
    buf.len = data_len;
    addr.sin_family = AF_INET;
    CPY_IPV4(&addr.sin_addr, dst);
    addr.sin_port = htons(dstport);
    return uv_udp_send(req, udp, &buf, 1, (struct sockaddr *)&addr, proxy_udp_send_cb);
}

int proxy_direct_init(struct proxy *proxy, uv_loop_t *loop, struct packet_ctx *packet_ctx)
{
    proxy->loop = loop;
    proxy->packet_ctx = packet_ctx;
    memset(&proxy->udp_table, 0, sizeof(proxy->udp_table));

    proxy->udp = proxy_direct_udp;
}
