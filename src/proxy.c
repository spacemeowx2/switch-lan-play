#include "proxy.h"
#include "helper.h"
#include "gateway.h"
#include "packet.h"
#include "ipv4/ipv4.h"
#include <assert.h>
#include <base/llog.h>
#if 0
#define malloc(size) ({ \
    void *__ptr = malloc(size); \
    LLOG(LLOG_DEBUG, "[malloc] %p %d %s:%d", __ptr, size, __FILE__, __LINE__); \
    __ptr; \
})
#endif
static void proxy_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void proxy_udp_send_cb(uv_udp_send_t *req, int status)
{
    if (status < 0) {
        LLOG(LLOG_ERROR, "proxy_udp_send_cb %d", status);
    }
    free(req->data);
    free(req);
}

static void proxy_udp_recv_cb(uv_udp_t *udp, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
    if (nread <= 0) {
        if (nread < 0) {
            LLOG(LLOG_DEBUG, "proxy_udp_recv_cb nread: %d", nread);
        }
        goto out;
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

out:
    free(buf->base);
}

static void cache_close_cb(uv_handle_t *udp)
{
    free(udp);
}

static void cache_delete_udp(struct proxy_udp_item *item)
{
    if (item->udp) {
        uv_udp_recv_stop(item->udp);
        uv_close((uv_handle_t *)item->udp, cache_close_cb);
        item->udp = NULL;
    }
}

static int cache_new_udp(struct proxy *proxy, struct proxy_udp_item *item, time_t now, uint8_t src[4], uint16_t srcport)
{
    if (item->udp) {
        cache_delete_udp(item);
    }
    item->udp = (uv_udp_t *)malloc(sizeof(uv_udp_t));
    if (item->udp == NULL) {
        return -1;
    }
    item->expire_at = now + PROXY_UDP_TABLE_TTL;
    item->proxy = proxy;

    int ret;
    ret = uv_udp_init(proxy->loop, item->udp);
    if (ret) return ret;
    ret = uv_udp_recv_start(item->udp, proxy_alloc_cb, proxy_udp_recv_cb);
    if (ret) return ret;
    item->udp->data = item;

    CPY_IPV4(item->src, src);
    item->srcport = srcport;

    return 0;
}

// Get or add in the table, return NULL if failed
static uv_udp_t *cache_get_udp(struct proxy *proxy, uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport)
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
            if (cache_new_udp(proxy, item, now, src, srcport) != 0) {
                return NULL;
            }
            return item->udp;
        }
    }

    return NULL;
}

static void cache_clear(struct proxy *proxy)
{
    struct proxy_udp_item *items = proxy->udp_table;
    int i;
    for (i = 0; i < PROXY_UDP_TABLE_LEN; i++) {
        struct proxy_udp_item *item = &items[i];
        if (item->udp) {
            cache_delete_udp(item);
        }
    }
}

static int direct_udp(struct proxy *proxy, uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport, const void *data, uint16_t data_len)
{
    uv_udp_t *udp = cache_get_udp(proxy, src, srcport, dst, dstport);
    if (udp == NULL) {
        LLOG(LLOG_WARNING, "cache_get_udp failed");
        return -1;
    }

    uv_udp_send_t *req = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));
    req->data = malloc(data_len);
    memcpy(req->data, data, data_len);

    uv_buf_t buf;
    struct sockaddr_in addr;

    buf.base = (char *)req->data;
    buf.len = data_len;

    addr.sin_family = AF_INET;
    CPY_IPV4(&addr.sin_addr, dst);
    addr.sin_port = htons(dstport);

    return uv_udp_send(req, udp, &buf, 1, (struct sockaddr *)&addr, proxy_udp_send_cb);
}

// static proxy_tcp_t *direct_tcp_new(struct proxy *proxy)
// {
//     uv_tcp_t *tcp = malloc(sizeof(uv_tcp_t));

//     if (uv_tcp_init(proxy->loop, tcp)) {
//         free(tcp);
//         tcp = NULL;
//     }

//     return (proxy_tcp_t *)tcp;
// }

// struct direct_tcp_connect_req {
//     uv_connect_t req;
//     proxy_connect_cb cb;
//     struct proxy *proxy;
//     uv_tcp_t *tcp;
// };

// static void direct_tcp_connect_cb(uv_connect_t *r, int status)
// {
//     struct direct_tcp_connect_req *req = r->data;

//     if (status == 0) {
//         req->cb(req->proxy, (proxy_tcp_t *)req->tcp);
//     } else {
//         req->cb(req->proxy, NULL);
//         free(req->tcp);
//     }

//     free(req);
// }

// static int direct_tcp_connect(struct proxy *proxy, const struct sockaddr *addr, proxy_connect_cb cb)
// {
//     uv_tcp_t *tcp = malloc(sizeof(uv_tcp_t));

//     if (uv_tcp_init(proxy->loop, tcp)) {
//         free(tcp);
//         return -1;
//     }

//     struct direct_tcp_connect_req *req = malloc(sizeof(struct direct_tcp_connect_req));

//     req->proxy = proxy;
//     req->req.data = req;
//     req->cb = cb;
//     req->tcp = tcp;

//     return uv_tcp_connect(&req->req, tcp, addr, direct_tcp_connect_cb);
// }

static void proxy_direct_close(struct proxy *proxy)
{
    cache_clear(proxy);
}

int proxy_direct_init(struct proxy *proxy, uv_loop_t *loop, struct packet_ctx *packet_ctx)
{
    proxy->loop = loop;
    proxy->packet_ctx = packet_ctx;
    memset(&proxy->udp_table, 0, sizeof(proxy->udp_table));

    proxy->udp = direct_udp;
    proxy->close = proxy_direct_close;

    return 0;
}
