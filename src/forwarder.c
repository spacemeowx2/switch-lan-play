#include "lan-play.h"

enum forwarder_type {
    FORWARDER_TYPE_KEEPALIVE = 0x00,
    FORWARDER_TYPE_IPV4 = 0x01,
};
uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int forwarder_send_keepalive(struct lan_play *lan_play);
int forwarder_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len);

void forwarder_init(struct lan_play *lan_play)
{
    ssize_t ret;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct hostent *server_net;
    struct sockaddr_in *server_addr = &lan_play->server_addr;

    if (fd < 0) {
        fprintf(stderr, "Error socket %s\n", strerror(errno));
        exit(1);
    }
    lan_play->f_fd = fd;

    server_net = gethostbyname(SERVER_ADDR);
    if (server_net == NULL) {
        fprintf(stderr, "Error gethostbyname %s\n", strerror(errno));
        exit(1);
    }
    // printf("Server IP: ");
    // PRINT_IP(server_net->h_addr);
    // putchar('\n');

    server_addr->sin_family = AF_INET;
    server_addr->sin_addr = *((struct in_addr *)server_net->h_addr);
    server_addr->sin_port = htons(SERVER_PORT);

    ret = forwarder_send_keepalive(lan_play);
    if (ret != 0) {
        LLOG(LLOG_ERROR,  "Error forwarder keepalive %s\n", strerror(errno));
        exit(1);
    }

    puts("Forwarder connected");

    if (pthread_mutex_init(&lan_play->mutex, NULL) != 0) {
        fprintf(stderr, "Error pthread_mutex_init %s\n", strerror(errno));
        exit(1);
    }
}

int forwarder_process(struct lan_play *lan_play, const uint8_t *packet, uint16_t len)
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

void *forwarder_keepalive(void *p)
{
    struct lan_play *lan_play = (struct lan_play *)p;
    int fd = lan_play->f_fd;
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    while (1) {
        sleep(10);
        forwarder_send_keepalive(lan_play);
    }
}

void *forwarder_thread(void *p)
{
    struct lan_play *lan_play = (struct lan_play *)p;
    uint8_t buffer[BUFFER_SIZE];
    ssize_t recv_len = 0;
    socklen_t fromlen;
    int fd = lan_play->f_fd;
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    pthread_t keepalive_tid;

    pthread_create(&keepalive_tid, NULL, forwarder_keepalive, p);

    while (1) {
        fromlen = sizeof(*server_addr);
        recv_len = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)server_addr, &fromlen);
        if (recv_len == -1) {
            LLOG(LLOG_ERROR,  "Error forwarder recvfrom %s", strerror(errno));
            break;
        }
        switch (buffer[0]) { // type
        case FORWARDER_TYPE_KEEPALIVE:
            break;
        case FORWARDER_TYPE_IPV4:
            forwarder_process(lan_play, buffer + 1, recv_len);
            break;
        }
    }

    fprintf(stderr, "Forwarder server disconnected\n");
    exit(1);

    return NULL;
}

int forwarder_send(struct lan_play *lan_play, const uint8_t type, const void *packet, uint16_t len)
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

int forwarder_send_keepalive(struct lan_play *lan_play)
{
    return forwarder_send(lan_play, FORWARDER_TYPE_KEEPALIVE, NULL, 0);
}

int forwarder_send_ipv4(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    return forwarder_send(lan_play, FORWARDER_TYPE_IPV4, packet, len);
}
