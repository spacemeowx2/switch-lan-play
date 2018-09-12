#include "lan-play.h"

enum lan_client_type {
    LAN_CLIENT_TYPE_KEEPALIVE = 0x00,
    LAN_CLIENT_TYPE_IPV4 = 0x01,
};
uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void lan_client_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
void lan_client_keepalive_timer(uv_timer_t* handle);
int lan_client_send_keepalive(struct lan_play *lan_play);
int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

static void lan_client_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
  LLOG(LLOG_DEBUG, "lan_client_alloc_cb %p %d", handle, suggested_size);
}

int lan_client_init(struct lan_play *lan_play)
{
    int ret;
    uv_loop_t *loop = &lan_play->loop;
    uv_udp_t *client = &lan_play->client;
    uv_timer_t *timer = &lan_play->client_keepalive_timer;

    ret = uv_udp_init(loop, client);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_udp_init %d", ret);
    }
    client->data = lan_play;

    ret = uv_timer_init(loop, timer);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_init %d", ret);
    }
    timer->data = lan_play;

    printf("Server IP: %s\n", ip2str(&lan_play->server_addr.sin_addr));

    ret = uv_timer_start(timer, lan_client_keepalive_timer, 0, 10 * 1000);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_start %d", ret);
        return ret;
    }

    ret = uv_udp_recv_start(client, lan_client_alloc_cb, lan_client_on_recv);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_udp_recv_start %d", ret);
        return ret;
    }

    return ret;
}

int lan_client_process(struct lan_play *lan_play, const uint8_t *packet, uint16_t len)
{
    if (len == 0) {
        return 0;
    }
    uint8_t dst_mac[6];
    const uint8_t *dst = packet + IPV4_OFF_DST;
    struct payload part;

    if (lan_play->dev == NULL) {
        printf("not ready\n");
        return 1;
    }

    if (IS_BROADCAST(dst, lan_play->packet_ctx.subnet_net, lan_play->packet_ctx.subnet_mask)) {
        CPY_MAC(dst_mac, BROADCAST_MAC);
    } else if (!arp_get_mac_by_ip(&lan_play->packet_ctx, dst_mac, dst)) {
        return 0;
    }

    part.ptr = packet;
    part.len = len;
    part.next = NULL;
    return send_ether(
        &lan_play->packet_ctx,
        dst_mac,
        ETHER_TYPE_IPV4,
        &part
    );
}

void lan_client_keepalive_timer(uv_timer_t* handle)
{
    struct lan_play *lan_play = (struct lan_play *)handle->data;
    lan_client_send_keepalive(lan_play);
}

void lan_client_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    struct lan_play *lan_play = (struct lan_play *)handle->data;
    uint16_t recv_len = buf->len;
    uint8_t *buffer = (uint8_t *)buf->base;

    switch (buffer[0]) { // type
    case LAN_CLIENT_TYPE_KEEPALIVE:
        break;
    case LAN_CLIENT_TYPE_IPV4:
        lan_client_process(lan_play, buffer + 1, recv_len);
        break;
    }
}

void lan_client_on_sent(uv_udp_send_t* req, int status)
{

}

int lan_client_send(struct lan_play *lan_play, const uint8_t type, const void *packet, uint16_t len)
{
    struct sockaddr *server_addr = (struct sockaddr *)&lan_play->server_addr;
    int ret;
    uv_buf_t *bufs = lan_play->client_send_buf;
    int bufs_len = 1;
    bufs[0] = uv_buf_init((char *)&type, sizeof(type));
    if (packet) {
        bufs[1] = uv_buf_init((char *)packet, len);
        bufs_len = 2;
    }

    uv_udp_send_t req;
    ret = uv_udp_send(&req, &lan_play->client, bufs, bufs_len, server_addr, lan_client_on_sent);

    return ret;
}

int lan_client_send_keepalive(struct lan_play *lan_play)
{
    return lan_client_send(lan_play, LAN_CLIENT_TYPE_KEEPALIVE, NULL, 0);
}

int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    return lan_client_send(lan_play, LAN_CLIENT_TYPE_IPV4, packet, len);
}
