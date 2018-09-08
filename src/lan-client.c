#include "lan-play.h"

enum lan_client_type {
    LAN_CLIENT_TYPE_KEEPALIVE = 0x00,
    LAN_CLIENT_TYPE_IPV4 = 0x01,
};
uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int lan_client_send_keepalive(struct lan_play *lan_play);
int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

void lan_client_init(struct lan_play *lan_play)
{
    int ret;

    ret = uv_udp_init(&lan_play->loop, &lan_play->client);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_udp_init %d", ret);
    }

    ret = lan_client_send_keepalive(lan_play);
    if (ret != 0) {
        LLOG(LLOG_ERROR,  "Error lan_client keepalive %s\n", strerror(errno));
        exit(1);
    }

    puts("Forwarder connected");
    printf("Server IP: %s\n", ip2str(&lan_play->server_addr.sin_addr));

    if (pthread_mutex_init(&lan_play->mutex, NULL) != 0) {
        fprintf(stderr, "Error pthread_mutex_init %s\n", strerror(errno));
        exit(1);
    }
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

    if (IS_BROADCAST(dst, lan_play->subnet_net, lan_play->subnet_mask)) {
        CPY_MAC(dst_mac, BROADCAST_MAC);
    } else if (!arp_get_mac_by_ip(lan_play, dst_mac, dst)) {
        return 0;
    }

    part.ptr = packet;
    part.len = len;
    part.next = NULL;
    return send_ether(
        lan_play,
        dst_mac,
        ETHER_TYPE_IPV4,
        &part
    );
}

void *lan_client_keepalive(void *p)
{
    struct lan_play *lan_play = (struct lan_play *)p;
    int fd = lan_play->f_fd;
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    while (1) {
        sleep(10);
        lan_client_send_keepalive(lan_play);
    }
}

void *lan_client_thread(void *p)
{
    struct lan_play *lan_play = (struct lan_play *)p;
    uint8_t buffer[BUFFER_SIZE];
    ssize_t recv_len = 0;
    socklen_t fromlen;
    int fd = lan_play->f_fd;
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    pthread_t keepalive_tid;

    pthread_create(&keepalive_tid, NULL, lan_client_keepalive, p);

    while (1) {
        fromlen = sizeof(*server_addr);
        recv_len = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)server_addr, &fromlen);
        if (recv_len == -1) {
            LLOG(LLOG_ERROR,  "Error lan_client recvfrom %s", strerror(errno));
            break;
        }
        switch (buffer[0]) { // type
        case LAN_CLIENT_TYPE_KEEPALIVE:
            break;
        case LAN_CLIENT_TYPE_IPV4:
            lan_client_process(lan_play, buffer + 1, recv_len);
            break;
        }
    }

    fprintf(stderr, "Forwarder server disconnected\n");
    exit(1);

    return NULL;
}

int lan_client_send(struct lan_play *lan_play, const uint8_t type, const void *packet, uint16_t len)
{
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    struct msghdr msg;
    struct iovec iov[2];

    iov[0].iov_base = (void *)&type;
    iov[0].iov_len = sizeof(type);

    iov[1].iov_base = (void *)packet;
    iov[1].iov_len = len;

    msg.msg_name = server_addr;
    msg.msg_namelen = sizeof(*server_addr);
    msg.msg_iov = iov;
    if (packet == NULL) {
        msg.msg_iovlen = 1;
    } else {
        msg.msg_iovlen = 2;
    }
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    int ret = sendmsg(lan_play->f_fd, &msg, 0);
    return ret == -1 ? 1 : 0;
}

int lan_client_send_keepalive(struct lan_play *lan_play)
{
    return lan_client_send(lan_play, LAN_CLIENT_TYPE_KEEPALIVE, NULL, 0);
}

int lan_client_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    return lan_client_send(lan_play, LAN_CLIENT_TYPE_IPV4, packet, len);
}
