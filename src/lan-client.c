#include "lan-play.h"

struct lan_client_fragment_header {
    uint8_t src[4];
    uint8_t dst[4];
    uint16_t id;
    uint8_t part;
    uint8_t total_part;
    uint16_t len;
    uint16_t pmtu;
};
#define LC_FRAG_SRC 0
#define LC_FRAG_DST 4
#define LC_FRAG_ID 8
#define LC_FRAG_PART 10
#define LC_FRAG_TOTAL_PART 11
#define LC_FRAG_LEN 12
#define LC_FRAG_PMTU 14
#define LC_FRAG_HEADER_LEN 16

enum lan_client_type {
    LAN_CLIENT_TYPE_KEEPALIVE = 0x00,
    LAN_CLIENT_TYPE_IPV4 = 0x01,
    LAN_CLIENT_TYPE_PING = 0x02,
    LAN_CLIENT_TYPE_IPV4_FRAG = 0x03
};
struct ipv4_req {
    uv_udp_send_t req;
    char *packet;
};
uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void lan_client_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
void lan_client_keepalive_timer(uv_timer_t *handle);
void lan_client_real_broadcast_timer(uv_timer_t *handle);
int lan_client_send_keepalive(struct lan_play *lan_play);
int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

static void lan_client_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    struct lan_play *lan_play = handle->data;
    buf->base = (char *)lan_play->client_buf;
    buf->len = sizeof(lan_play->client_buf);
}

int lan_client_init(struct lan_play *lan_play)
{
    int ret;
    uv_loop_t *loop = lan_play->loop;
    uv_udp_t *client = &lan_play->client;
    uv_timer_t *client_keepalive_timer = &lan_play->client_keepalive_timer;
    uv_timer_t *real_broadcast_timer = &lan_play->real_broadcast_timer;

    if (lan_play->pmtu) {
        if (lan_play->pmtu < MIN_FRAG_PAYLOAD_LEN) {
            LLOG(LLOG_DEBUG, "pmtu is too small: %d, must be greater than %d", lan_play->pmtu, MIN_FRAG_PAYLOAD_LEN);
            exit(1);
        }
        LLOG(LLOG_DEBUG, "pmtu is set to %d", lan_play->pmtu);
    }
    lan_play->frag_id = 0;
    lan_play->local_id = 0;
    lan_play->next_real_broadcast = true;
    memset(&lan_play->frags, 0, sizeof(lan_play->frags));

    ret = uv_udp_init(loop, client);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_udp_init %d", ret);
    }

    if (lan_play->broadcast) {
        struct sockaddr_in temp;
        uv_ip4_addr("0.0.0.0", 11451, &temp);
        ret = uv_udp_bind(client, (struct sockaddr *)&temp, 0);
        if (ret != 0) {
            LLOG(LLOG_ERROR, "uv_udp_bind %d", ret);
        }
    }

    ret = uv_timer_init(loop, client_keepalive_timer);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_init %d", ret);
    }

    ret = uv_timer_init(loop, real_broadcast_timer);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_init %d", ret);
    }

    client->data = lan_play;
    client_keepalive_timer->data = lan_play;
    real_broadcast_timer->data = lan_play;

    printf("Server IP: %s\n", ip2str(&lan_play->server_addr.sin_addr));

    ret = uv_timer_start(client_keepalive_timer, lan_client_keepalive_timer, 0, 10 * 1000);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_start %d", ret);
        return ret;
    }

    ret = uv_timer_start(real_broadcast_timer, lan_client_real_broadcast_timer, 0, 1000);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_start %d", ret);
        return ret;
    }

    ret = uv_udp_recv_start(client, lan_client_alloc_cb, lan_client_on_recv);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_udp_recv_start %d", ret);
        return ret;
    }

    lan_play->upload_byte = 0;
    lan_play->download_byte = 0;
    lan_play->upload_packet = 0;
    lan_play->download_packet = 0;

    return ret;
}

int lan_client_close(struct lan_play *lan_play)
{
    int ret;

    ret = uv_udp_recv_stop(&lan_play->client);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_udp_recv_stop %d", ret);
        return ret;
    }

    ret = uv_timer_stop(&lan_play->client_keepalive_timer);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_timer_stop %d", ret);
        return ret;
    }

    ret = uv_timer_stop(&lan_play->real_broadcast_timer);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "real_broadcast uv_timer_stop %d", ret);
        return ret;
    }

    uv_close((uv_handle_t *)&lan_play->client, NULL);
    uv_close((uv_handle_t *)&lan_play->client_keepalive_timer, NULL);

    return 0;
}

int lan_client_arp_for_each_cb(void *p, const struct arp_item *item)
{
    struct {
        struct lan_play *lan_play;
        const uint8_t *packet;
        uint16_t len;
    } *userdata = p;

    // TODO: check subnet
    // const uint8_t *dst = userdata->packet + IPV4_OFF_DST;
    struct payload part;

    part.ptr = userdata->packet;
    part.len = userdata->len;
    part.next = NULL;
    int rc = send_ether(
        &userdata->lan_play->packet_ctx,
        item->mac,
        ETHER_TYPE_IPV4,
        &part
    );
    if (rc != 0) {
        LLOG(LLOG_ERROR, "Failed to call send_ether in lan_client_arp_for_each_cb");
    }

    return 0;
}

int lan_client_on_broadcast(struct lan_play *lan_play, const uint8_t *packet, uint16_t len)
{
    if (lan_play->next_real_broadcast) {
        lan_play->next_real_broadcast = false;

        struct payload part;

        part.ptr = packet;
        part.len = len;
        part.next = NULL;
        return send_ether(
            &lan_play->packet_ctx,
            BROADCAST_MAC,
            ETHER_TYPE_IPV4,
            &part
        );
    } else {
        struct {
            struct lan_play *lan_play;
            const uint8_t *packet;
            uint16_t len;
        } userdata;
        userdata.lan_play = lan_play;
        userdata.packet = packet;
        userdata.len = len;
        arp_for_each(&lan_play->packet_ctx, &userdata, lan_client_arp_for_each_cb);
    }
    return 0;
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
        return lan_client_on_broadcast(lan_play, packet, len);
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

int lan_client_process_frag(struct lan_play *lan_play, const uint8_t *packet, uint16_t len)
{

    struct lan_client_fragment *frags = lan_play->frags;
    struct lan_client_fragment_header header;
    CPY_IPV4(header.src, packet + LC_FRAG_SRC);
    CPY_IPV4(header.dst, packet + LC_FRAG_DST);
    header.id = READ_NET16(packet, LC_FRAG_ID);
    header.part = READ_NET8(packet, LC_FRAG_PART);
    header.total_part = READ_NET8(packet, LC_FRAG_TOTAL_PART);
    header.len = READ_NET16(packet, LC_FRAG_LEN);
    header.pmtu = READ_NET16(packet, LC_FRAG_PMTU);

    LLOG(LLOG_DEBUG, "lan_client_process_frag %d:%d/%d", header.id, header.part, header.total_part);
    struct lan_client_fragment *frag = NULL;
    int i;
    for (i = 0; i < LC_FRAG_COUNT; i++) {
        if (frags[i].used
                && (frags[i].id == header.id)
                && CMP_IPV4(frags[i].src, header.src)) {
            frag = &frags[i];
            break;
        }
    }

    if (!frag) {
        for (i = 0; i < LC_FRAG_COUNT; i++) {
            if (!frags[i].used) {
                frag = &frags[i];
                frag->used = 1;
                frag->id = header.id;
                frag->local_id = lan_play->local_id++;
                CPY_IPV4(frag->src, header.src);
                frag->part = 0;
                break;
            }
        }
    }

    if (!frag) {
        int max_dif = 0;
        struct lan_client_fragment *to_delete = NULL;
        for (i = 0; i < LC_FRAG_COUNT; i++) {
            if (frags[i].used) {
                int dif = LABS(frags[i].local_id - lan_play->local_id);
                if (dif > max_dif) {
                    max_dif = dif;
                    to_delete = &frags[i];
                }
            }
        }
        if (max_dif > LC_FRAG_COUNT) {
            LLOG(LLOG_DEBUG, "fragment buffer is full, deleting id %d", to_delete->id);
            frag = to_delete;
            frag->used = 1;
            frag->id = header.id;
            frag->local_id = lan_play->local_id++;
            CPY_IPV4(frag->src, header.src);
            frag->part = 0;
        }
    }

    if (frag) {
        frag->part |= 1 << header.part;
        memcpy(&frag->buffer[header.pmtu * header.part], packet + LC_FRAG_HEADER_LEN, header.len);
        if (header.part == header.total_part - 1) {
            frag->total_len = (header.total_part - 1) * header.pmtu + header.len;
        }
        if (~(~0 << header.total_part) == frag->part) {
            LLOG(LLOG_DEBUG, "fragment finish %d, origin len %d", frag->id, frag->total_len);
            // finish
            frag->used = 0;
            return lan_client_process(lan_play, frag->buffer, frag->total_len);
        }
    } else {
        LLOG(LLOG_WARNING, "fragment buffer is full, ignore it");
    }

    return 0;
}

void lan_client_real_broadcast_timer(uv_timer_t *handle)
{
    struct lan_play *lan_play = (struct lan_play *)handle->data;
    lan_play->next_real_broadcast = true;
}

void lan_client_keepalive_timer(uv_timer_t *handle)
{
    struct lan_play *lan_play = (struct lan_play *)handle->data;
    lan_client_send_keepalive(lan_play);
}

void lan_client_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    if (nread <= 0) {
        if (nread < 0) {
            LLOG(LLOG_DEBUG, "lan_client_on_recv nread: %d", nread);
        }
        return;
    }
    struct lan_play *lan_play = (struct lan_play *)handle->data;
    uint16_t recv_len = nread;
    uint8_t *buffer = (uint8_t *)buf->base;

    lan_play->download_packet++;
    lan_play->download_byte += recv_len;

    switch (buffer[0]) { // type
    case LAN_CLIENT_TYPE_KEEPALIVE:
        break;
    case LAN_CLIENT_TYPE_IPV4:
        lan_client_process(lan_play, buffer + 1, recv_len - 1);
        break;
    case LAN_CLIENT_TYPE_IPV4_FRAG:
        lan_client_process_frag(lan_play, buffer + 1, recv_len - 1);
        break;
    }
}

void lan_client_on_sent(uv_udp_send_t* req, int status)
{
    if (status != 0) {
        LLOG(LLOG_DEBUG, "lan_client_on_sent %d, %s", status, uv_strerror(status));
    }
    struct ipv4_req *ipv4_req = req->data;
    free(ipv4_req->packet);
    free(ipv4_req);
}

static int lan_client_send_raw(struct lan_play *lan_play, uv_buf_t *bufs, int bufs_len)
{
    int i;
    int cur_pos;
    int total_len;
    int ret;
    struct sockaddr *server_addr = (struct sockaddr *)&lan_play->server_addr;
    struct ipv4_req *req = malloc(sizeof(struct ipv4_req));

    total_len = 0;
    for (i = 0; i < bufs_len; i++) {
        total_len += bufs[i].len;
    }

    req->packet = malloc(total_len);

    cur_pos = 0;
    for (i = 0; i < bufs_len; i++) {
        memcpy(req->packet + cur_pos, bufs[i].base, bufs[i].len);
        cur_pos += bufs[i].len;
    }

    uv_buf_t buf = uv_buf_init(req->packet, total_len);

    uv_udp_send_t *udp_req = &req->req;
    udp_req->data = req;
    ret = uv_udp_send(udp_req, &lan_play->client, &buf, 1, server_addr, lan_client_on_sent);

    lan_play->upload_packet++;
    lan_play->upload_byte += total_len;

    return ret;
}

int lan_client_send(struct lan_play *lan_play, uint8_t type, const uint8_t *packet, uint16_t len)
{
    uv_buf_t bufs[3];
    bufs[0] = uv_buf_init((char *)&type, sizeof(type));

    int pmtu = lan_play->pmtu;
    if (type == LAN_CLIENT_TYPE_IPV4 && pmtu > 0) {
        int ret = 0;
        int i, pos;
        int total_part;
        total_part = len / pmtu;
        if (pmtu * total_part < len) {
            total_part += 1;
        }
        if (total_part > 1) {
            type = LAN_CLIENT_TYPE_IPV4_FRAG;
            int id = lan_play->frag_id++;
            uint8_t header[LC_FRAG_HEADER_LEN];
            CPY_IPV4(header + LC_FRAG_SRC, packet + IPV4_OFF_SRC);
            CPY_IPV4(header + LC_FRAG_DST, packet + IPV4_OFF_DST);
            WRITE_NET8(header, LC_FRAG_TOTAL_PART, total_part);
            WRITE_NET16(header, LC_FRAG_PMTU, pmtu);
            bufs[1] = uv_buf_init((char *)&header, sizeof(header));

            i = 0;
            pos = 0;
            while (pos < len) {
                int part_len = LMIN(pmtu, len - pos);
                WRITE_NET16(header, LC_FRAG_ID, id);
                WRITE_NET8(header, LC_FRAG_PART, i);
                WRITE_NET16(header, LC_FRAG_LEN, part_len);

                bufs[2] = uv_buf_init((char *)(packet + pos), part_len);
                ret = lan_client_send_raw(lan_play, bufs, 3);
                if (ret) return ret;

                i += 1;
                pos += part_len;
            }
            return 0;
        }
    }

    bufs[1] = uv_buf_init((char *)packet, len);
    return lan_client_send_raw(lan_play, bufs, 2);
}

int lan_client_send_keepalive(struct lan_play *lan_play)
{
    return lan_client_send(lan_play, LAN_CLIENT_TYPE_KEEPALIVE, NULL, 0);
}

int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    return lan_client_send(lan_play, LAN_CLIENT_TYPE_IPV4, packet, len);
}
