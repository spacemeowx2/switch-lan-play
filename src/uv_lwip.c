#include "uv_lwip.h"
#include <base/llog.h>
#include <string.h>
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>
#include <lwip/ip4_frag.h>
#include <lwip/nd6.h>
#include <lwip/ip6_frag.h>

// #define _DEBUG
#define UVL_TCP_RECV_BUF_LEN TCP_WND
#define UVL_TCP_SEND_BUF_LEN 8192

struct uvl_tcp_buf {
    uint8_t recv_buf[UVL_TCP_RECV_BUF_LEN];
    uint16_t recv_used;
};

static uv_once_t uvl_init_once = UV_ONCE_INIT;
#define CONTAINER_OF(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) );    \
})
#define LMIN(a, b) ( ((a) < (b)) ? (a) : (b) )

static void uvl_imp_write_to_tcp(uvl_tcp_t *client);
static err_t uvl_client_close_func (uvl_tcp_t *client);

static void addr_from_lwip(void *ip, const ip_addr_t *ip_addr)
{
    if (IP_IS_V6(ip_addr)) {
        LLOG(LLOG_ERROR, "ipv6 not support now");
        return;
    } else {
        memcpy(ip, &ip_addr->u_addr.ip4.addr, 4);
    }
}

static void uvl_async_tcp_read_cb(uv_async_t *req)
{
    uvl_tcp_t *client = (uvl_tcp_t *)req->data;
    struct uvl_tcp_buf *buf = client->buf;
    uv_buf_t b;
    int nnread = 0;
    ASSERT(buf->recv_used <= sizeof(buf->recv_buf))

    if (client->read_cb) {
        if (buf->recv_used > 0) {
            client->alloc_cb(client, 65536, &b);

            if (b.base == NULL || b.len < buf->recv_used) {
                nnread = UV_ENOBUFS;
            } else {
                // LLOG(LLOG_DEBUG, "[-] recv_buf %d / %d", buf->recv_used, sizeof(buf->recv_buf));
                memcpy(b.base, buf->recv_buf, buf->recv_used);
                tcp_recved(client->pcb, buf->recv_used);
                nnread = buf->recv_used;
                buf->recv_used = 0;
            }
            client->read_cb(client, nnread, &b);
        }
    }
}

static void uvl_cancel_reqs(uvl_tcp_t *client)
{
    uvl_write_t *req = client->cur_write;
    uvl_write_t *next;

    while (req)
    {
        next = req->next;
        req->write_cb(req, UV_ECANCELED);
        req = next;
    }

    client->cur_write = NULL;
    client->tail_write = NULL;

    if (client->read_cb) {
        uv_buf_t null_buf = uv_buf_init(NULL, 0);
        client->read_cb(client, UV_ECANCELED, &null_buf);
        client->read_cb = NULL;
    }
}

// TODO: complete this function
static void uvl_async_tcp_write_cb(uv_async_t *write_req)
{
    uvl_tcp_t *client = (uvl_tcp_t *)write_req->data;

    if (client->closed) {
        uvl_cancel_reqs(client);
        return;
    }

    uvl_imp_write_to_tcp(client);
}

static int uvl_imp_write_buf_to_tcp(uvl_tcp_t *client, uvl_write_t *req)
{
    // LLOG(LLOG_DEBUG, "write_buf_to_tcp %d / %d", req->sent_bufs, req->send_nbufs);
    const uv_buf_t *buf = &req->send_bufs[req->sent_bufs];

    do {
        int to_write = LMIN(buf->len - req->sent, tcp_sndbuf(client->pcb));
        if (to_write == 0) {
            goto may_next; // tcp_sndbuf may be 0
        }

        err_t err = tcp_write(client->pcb, buf->base + req->sent, to_write, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            if (err == ERR_MEM) {
                return 0;
            }
            LLOG(LLOG_INFO, "tcp_write failed (%d)", (int)err);

            return uvl_client_close_func(client);
        }
        req->sent += to_write;
        req->pending += to_write;
        req->total_sent += to_write;
        client->recv_bytes += to_write;
    } while (req->sent < buf->len);

may_next:
    // LLOG(LLOG_DEBUG, "go next buf: %d/%d, total: %d/%d, sndbuf: %d", req->sent, buf->len, req->total_sent, req->total_len, tcp_sndbuf(client->pcb));
    if (tcp_sndbuf(client->pcb) == 0) {
        return 0;
    } else {
        req->sent = 0;
        req->sent_bufs++;
        return 1;
    }
}

/**
 * This function will be called in pool thread
 * or called from tcp_sent's callback.
 */
static void uvl_imp_write_to_tcp(uvl_tcp_t *client)
{
    ASSERT(client->cur_write)
    ASSERT(client->pcb)

    uvl_write_t *req = client->cur_write;

#ifdef _DEBUG
    int total = 0;
    int i = 1;

    while (req) {
        req = req->next;
        total++;
    }
    req = client->cur_write;
#endif

    while (req) {
        // LLOG(LLOG_DEBUG, "fuck %d / %d", req->sent_bufs, req->send_nbufs);
        if (req->sent_bufs < req->send_nbufs) {
            break;
        }
        req = req->next;
#ifdef _DEBUG
        i++;
#endif
    }

    while (req) {
#ifdef _DEBUG
        LLOG(LLOG_DEBUG, "%p block %d / %d", client, i, total);
#endif
        int ret = uvl_imp_write_buf_to_tcp(client, req);
        if (ret == 0) {
            break;
        }
        if (ret == -1) {
            return;
        }
        if (req->sent_bufs == req->send_nbufs) {
            req = req->next;
        }
    }

    err_t err = tcp_output(client->pcb);
    if (err != ERR_OK) {
        LLOG(LLOG_INFO, "tcp_output failed (%d)", (int)err);

        uvl_client_close_func(client);
        return;
    }
}

static void uvl_client_freed(uvl_tcp_t *client)
{
    LLOG(LLOG_DEBUG, "%p uvl_client_freed", client);

    client->pcb = NULL;
    client->closed = 1;

    if (client->read_cb) {
        uv_buf_t null_buf = uv_buf_init(NULL, 0);
        client->read_cb(client, UV_EOF, &null_buf);
        client->read_cb = NULL;
    }
}

static err_t uvl_client_abort (uvl_tcp_t *client)
{
    LLOG(LLOG_DEBUG, "uvl_client_abort");
    ASSERT(client->pcb)
    ASSERT(!client->closed)

//     // remove callbacks
    tcp_err(client->pcb, NULL);
    tcp_recv(client->pcb, NULL);
    tcp_sent(client->pcb, NULL);

    // abort
    tcp_abort(client->pcb);

    uvl_client_freed(client);

    return ERR_ABRT;
}

static err_t uvl_client_close_func (uvl_tcp_t *client)
{
    ASSERT(!client->closed)

    tcp_err(client->pcb, NULL);
    tcp_recv(client->pcb, NULL);
    tcp_sent(client->pcb, NULL);

    err_t err = tcp_close(client->pcb);

    if (err == ERR_OK) {
        uvl_client_freed(client);
    } else {
        LLOG(LLOG_ERROR, "tcp_close failed (%d)", err);
        err = uvl_client_abort(client);
    }

    return err;
}

static err_t uvl_client_recv_func (void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    uvl_tcp_t *client = (uvl_tcp_t *)arg;
    ASSERT(!client->closed)
    ASSERT(client->pcb == tpcb)
    ASSERT(err == ERR_OK)

    if (!p) {
        // close

        return uvl_client_close_func(client);
    } else {
        ASSERT(p->tot_len > 0)

        struct uvl_tcp_buf *buf = client->buf;

        if (p->tot_len > (sizeof(buf->recv_buf) - buf->recv_used)) {
            LLOG(LLOG_ERROR, "no buffer for data !?! %d, %d / %d, remain %d",
                p->tot_len,
                buf->recv_used,
                sizeof(buf->recv_buf),
                (sizeof(buf->recv_buf) - buf->recv_used));

            return ERR_MEM;
        }

        // LLOG(LLOG_DEBUG, "[+] recv_buf %d + %d / %d", buf->recv_used, p->tot_len, sizeof(buf->recv_buf));
        ASSERT(pbuf_copy_partial(p, buf->recv_buf + buf->recv_used, p->tot_len, 0) == p->tot_len)
        buf->recv_used += p->tot_len;

        pbuf_free(p);

        int ret = uv_async_send(&client->read_req);

        return ret == 0 ? ERR_OK : ERR_ABRT;
    }
}

static err_t uvl_client_sent_func (void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    uvl_tcp_t *client = (uvl_tcp_t *)arg;
    uvl_write_t *req = client->cur_write;
    uvl_write_t *next = NULL;

#ifdef _DEBUG
    int total = 0;
    int pre_total = 0;
    while (req) {
        req = req->next;
        pre_total++;
    }
    req = client->cur_write;
#endif

    ASSERT(!client->closed)
    ASSERT(len > 0)

    client->sent_bytes += len;

    while (len > 0) {
        int to_sub = LMIN(req->pending, len);
        req->pending -= to_sub;
        len -= to_sub;
        req = req->next;
    }

    req = client->cur_write;

    while (req && (req->total_sent == req->total_len) && (req->pending == 0)) {
        next = req->next; // save before it be freed
        // should call the callback
        req->write_cb(req, 0);

        req = next;
    }

    client->cur_write = req;

    if (client->cur_write == NULL) {
        client->tail_write = NULL;
    } else {
        int ret = uv_async_send(&client->write_req);
        if (ret) {
            LLOG(LLOG_ERROR, "sent_func async_send");
        }
    }

#ifdef _DEBUG
    while (req) {
        req = req->next;
        total++;
    }
    req = client->cur_write;
    LLOG(LLOG_DEBUG, "%p consume block len: %d -> %d. TS: %d RS: %d", client, pre_total, total, client->sent_bytes, client->recv_bytes);

    int i = 1;
    while (req) {
        LLOG(LLOG_DEBUG, "[%d] total: %d/%d pending: %d", i, req->total_sent, req->total_len, req->pending);

        req = req->next;
    }
#endif

    return ERR_OK;
}

static void uvl_client_err_func(void *arg, err_t err)
{
    uvl_tcp_t *client = arg;

    LLOG(LLOG_ERROR, "client err: %d", (int)err);

    uvl_client_freed(client);
}

static err_t uvl_listener_accept_func (void *arg, struct tcp_pcb *newpcb, err_t err)
{
    uvl_t *handle = (uvl_t *)arg;

    ASSERT(err == ERR_OK)
    ASSERT(handle->listener)
    ASSERT(handle->connection_cb)

    handle->waiting_pcb = newpcb;
    handle->connection_cb(handle, 0);

    // not accept?
    if (handle->waiting_pcb != NULL) {
        // send rst
        goto fail_abort;
    }

    return ERR_OK;
fail_abort:
    tcp_abort(newpcb);
    handle->waiting_pcb = NULL;
    return ERR_ABRT;
}

static err_t uvl_netif_output_func (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    uvl_t *handle = (uvl_t *)netif->state;
    uv_buf_t bufs[UVL_NBUF_LEN];
    int ret;
    int i = 0;

    do {
        bufs[i].base = p->payload;
        bufs[i].len = p->len;
        i += 1;
    } while ((p = p->next));
    assert(i < UVL_NBUF_LEN);

    ret = handle->output(handle, bufs, i);

    if (ret != 0) {
        LLOG(LLOG_ERROR, "uvl->output %d", ret);
    }

    return ret == 0 ? ERR_OK : ERR_IF;
}

static err_t uvl_netif_init_func (struct netif *netif)
{
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = uvl_netif_output_func;

    return ERR_OK;
}


static err_t uvl_netif_input_func(struct pbuf *p, struct netif *inp)
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

int uvl_read_start(uvl_tcp_t *client, uvl_alloc_cb alloc_cb, uvl_read_cb read_cb)
{
    if (client->read_cb) {
        return UV_EALREADY;
    }

    if (client->closed) {
        uv_buf_t null_buf = uv_buf_init(NULL, 0);
        read_cb(client, UV_EOF, &null_buf);
        return 0;
    }

    int err = uv_async_send(&client->read_req);

    if (!err) {
        client->alloc_cb = alloc_cb;
        client->read_cb = read_cb;
    }

    return err;
}

int uvl_read_stop(uvl_tcp_t *client)
{
    client->alloc_cb = NULL;
    client->read_cb = NULL;

    return 0;
}

int uvl_write(uvl_write_t *req, uvl_tcp_t *client, const uv_buf_t bufs[], unsigned int nbufs, uvl_write_cb cb)
{
    req->client = client;

    int i;

    req->send_bufs = bufs;
    req->send_nbufs = nbufs;
    req->sent = 0;
    req->pending = 0;
    req->sent_bufs = 0;
    req->total_sent = 0;
    req->total_len = 0;
    req->write_cb = cb;

    req->next = NULL;

    if (client->tail_write) {
        client->tail_write->next = req;
    }
    client->tail_write = req;
    if (client->cur_write == NULL) {
        client->cur_write = req;
    }

    for (i = 0; i < nbufs; i++) {
        req->total_len += bufs[i].len;
    }

    return uv_async_send(&client->write_req);
}

int uvl_accept(uvl_t *handle, uvl_tcp_t *client)
{
    ASSERT(handle->waiting_pcb)
    ASSERT(client->loop == handle->loop)
    ASSERT(client->handle == NULL)

    struct tcp_pcb *newpcb = handle->waiting_pcb;
    uint8_t local_addr[4];
    uint8_t remote_addr[4];

    addr_from_lwip(local_addr, &newpcb->local_ip);
    addr_from_lwip(remote_addr, &newpcb->remote_ip);

    client->handle = handle;
    client->pcb = newpcb;

    client->local_addr.sin_family = AF_INET;
    client->local_addr.sin_addr = *((struct in_addr *)local_addr);
    client->local_addr.sin_port = htons(newpcb->local_port);

    client->remote_addr.sin_family = AF_INET;
    client->remote_addr.sin_addr = *((struct in_addr *)remote_addr);
    client->remote_addr.sin_port = htons(newpcb->remote_port);

    client->sent_bytes = 0;
    client->recv_bytes = 0;
    client->closed_handle = 0;

    tcp_arg(newpcb, client);

    tcp_err(newpcb, uvl_client_err_func);
    tcp_recv(newpcb, uvl_client_recv_func);
    tcp_sent(newpcb, uvl_client_sent_func);

    handle->waiting_pcb = NULL;

    return 0;
}

int uvl_close(uvl_t *handle, uvl_close_cb close_cb)
{
    // TODO: abort all connections, then:
    // tcp_close(handle->listener);
    // netif_remove(&the_netif);

    close_cb(handle);

    return 0;
}

static int uvl_init_lwip(uvl_t *handle)
{
    struct netif *the_netif = (struct netif *)malloc(sizeof(struct netif));
    handle->the_netif = the_netif;

    uv_once(&uvl_init_once, lwip_init);

    // make addresses for netif
    ip4_addr_t addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    ip4_addr_set_any(&addr);
    ip4_addr_set_any(&netmask);
    ip4_addr_set_any(&gw);
    if (!netif_add(the_netif, &addr, &netmask, &gw, handle /* state */, uvl_netif_init_func, uvl_netif_input_func)) {
        LLOG(LLOG_ERROR, "netif_add failed");
        goto fail;
    }

    // the_netif->mtu = 200;

    // set netif up
    netif_set_up(the_netif);

    // set netif link up, otherwise ip route will refuse to route
    netif_set_link_up(the_netif);

    // set netif pretend TCP
    netif_set_pretend_tcp(the_netif, 1);

    // set netif default
    netif_set_default(the_netif);

    return 0;
fail:
    return -1;
}

int uvl_tcp_init(uv_loop_t *loop, uvl_tcp_t *client)
{
    int ret;

    client->loop = loop;
    client->handle = NULL;
    client->read_cb = NULL;
    client->alloc_cb = NULL;
    client->close_cb = NULL;
    client->buf = (struct uvl_tcp_buf *)malloc(sizeof(struct uvl_tcp_buf));
    client->buf->recv_used = 0;
    client->cur_write = NULL;
    client->tail_write = NULL;
    client->pcb = NULL;
    client->closed = 0;

    LLOG(LLOG_DEBUG, "buffer size %d", sizeof(client->buf->recv_buf));

    ret = uv_async_init(loop, &client->read_req, uvl_async_tcp_read_cb);
    if (ret) return ret;
    client->read_req.data = client;

    ret = uv_async_init(loop, &client->write_req, uvl_async_tcp_write_cb);
    if (ret) return ret;
    client->write_req.data = client;

    memset(&client->local_addr, 0, sizeof(client->local_addr));
    memset(&client->remote_addr, 0, sizeof(client->remote_addr));

    return 0;
}

static void uvl_tcp_close_handle_cb(uv_handle_t *handle)
{
    uvl_tcp_t *client = handle->data;

    client->closed_handle++;
    if (client->closed_handle == 2) {
        client->loop = NULL;
        client->handle = NULL;
        free(client->buf);
        client->buf = NULL;
        client->cur_write = NULL;
        client->tail_write = NULL;
        client->alloc_cb = NULL;
        client->read_cb = NULL;
        client->pcb = NULL;
        client->closed_handle = 0;

        uvl_tcp_close_cb cb = client->close_cb;
        client->close_cb = NULL;
        cb(client);
    }
}

int uvl_tcp_close(uvl_tcp_t *client, uvl_tcp_close_cb cb)
{
    ASSERT(client->close_cb == NULL || client->close_cb == cb)

    if (!client->closed) {
        uvl_client_close_func(client);
    }

    uvl_cancel_reqs(client);

    uv_close((uv_handle_t *)&client->read_req, uvl_tcp_close_handle_cb);
    uv_close((uv_handle_t *)&client->write_req, uvl_tcp_close_handle_cb);

    client->close_cb = cb;

    return 0;
}

static void uvl_timer(uv_timer_t *timer)
{
    uvl_t *handle = timer->data;

    handle->tcp_timer_mod4 = (handle->tcp_timer_mod4 + 1) % 4;
    tcp_tmr();

    if (handle->tcp_timer_mod4 == 0) {
#if IP_REASSEMBLY
        ASSERT(IP_TMR_INTERVAL == 4 * TCP_TMR_INTERVAL)
        ip_reass_tmr();
#endif

#if LWIP_IPV6
        ASSERT(ND6_TMR_INTERVAL == 4 * TCP_TMR_INTERVAL)
        nd6_tmr();
#endif

#if LWIP_IPV6 && LWIP_IPV6_REASS
        ASSERT(IP6_REASS_TMR_INTERVAL == 4 * TCP_TMR_INTERVAL)
        ip6_reass_tmr();
#endif
    }
}

int uvl_init(uv_loop_t *loop, uvl_t *handle)
{
    handle->loop = loop;
    handle->output = NULL;
    handle->connection_cb = NULL;

    handle->listener = NULL;
    handle->waiting_pcb = NULL;

    int ret;

    ret = uv_timer_init(loop, &handle->timer);
    if (ret) return ret;
    handle->timer.data = handle;
    ret = uv_timer_start(&handle->timer, uvl_timer, 0, 250);
    if (ret) return ret;

    return uvl_init_lwip(handle);
}

int uvl_bind(uvl_t *handle, uvl_output_fn output)
{
    handle->output = output;

    return 0;
}

int uvl_input(uvl_t *handle, const uv_buf_t buf)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, buf.len, PBUF_POOL);

    if (!p) {
        LLOG(LLOG_WARNING, "device read: pbuf_alloc failed");
        return -1;
    }

    if (pbuf_take(p, buf.base, buf.len) != ERR_OK) {
        LLOG(LLOG_ERROR, "pbuf_take");
        return -1;
    }

    if (handle->the_netif->input(p, handle->the_netif) != ERR_OK) {
        LLOG(LLOG_WARNING, "device read: input failed");
        pbuf_free(p);
    }

    return 0;
fail:
    return -1;
}

int uvl_listen(uvl_t *handle, uvl_connection_cb connection_cb)
{
    handle->connection_cb = connection_cb;

    // init listener
    struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!l) {
        LLOG(LLOG_ERROR, "tcp_new_ip_type failed");
        goto fail;
    }

    // bind listener TODO: multiple netif support ?
    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
        LLOG(LLOG_ERROR, "tcp_bind_to_netif failed");
        tcp_close(l);
        goto fail;
    }

    // ensure the listener only accepts connections from this netif
    // tcp_bind_netif(l, the_netif);

    // listen listener
    if (!(handle->listener = tcp_listen(l))) {
        LLOG(LLOG_ERROR, "tcp_listen failed");
        tcp_close(l);
        goto fail;
    }

    tcp_arg(handle->listener, handle);
    // setup listener accept handler
    tcp_accept(handle->listener, uvl_listener_accept_func);

    return 0;
fail:
    return -1;
}
