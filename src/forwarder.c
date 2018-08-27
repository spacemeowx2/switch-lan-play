#include "lan-play.h"

uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void forwarder_init(struct lan_play *lan_play)
{
    int ret;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct hostent *server_net;
    struct sockaddr_in *server_addr = &lan_play->server_addr;

    if (fd < 0) {
        fprintf(stderr, "Error socket %s\n", strerror(errno));
        exit(1);
    }

    server_net = gethostbyname(SERVER_ADDR);
    if (server_net == NULL) {
        fprintf(stderr, "Error gethostbyname %s\n", strerror(errno));
        exit(1);
    }
    printf("Server IP: ");
    PRINT_IP(server_net->h_addr);
    putchar('\n');

    server_addr->sin_family = AF_INET;
    server_addr->sin_addr = *((struct in_addr *)server_net->h_addr);
    server_addr->sin_port = htons(SERVER_PORT);

    // ret = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    // if (ret != 0) {
    //     fprintf(stderr, "Error connect %d\n", ret);
    //     exit(1);
    // }
    uint32_t empty = 0;
    sendto(fd, (char *)&empty, 4, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));

    puts("Forwarder connected");
    lan_play->f_fd = fd;

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
        uint32_t empty = 0;
        sendto(fd, (char *)&empty, 4, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
        sleep(10);
    }
}

void *forwarder_thread(void *p)
{
    struct lan_play *lan_play = (struct lan_play *)p;
    uint8_t buffer[BUFFER_SIZE];
    uint32_t buf_len = 0;
    uint32_t recv_len = 0;
    int32_t wait_len = -1;
    socklen_t fromlen;
    int fd = lan_play->f_fd;
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    pthread_t keepalive_tid;

    pthread_create(&keepalive_tid, NULL, forwarder_keepalive, p);

    while (1) {
        fromlen = sizeof(*server_addr);
        recv_len = recvfrom(fd, buffer + buf_len, BUFFER_SIZE - buf_len, 0, (struct sockaddr *)server_addr, &fromlen);
        if (recv_len >= 20) {
            forwarder_process(lan_play, buffer, recv_len);
        }
    }

    fprintf(stderr, "Forwarder server disconnected\n");
    exit(1);

    return NULL;
}

int forwarder_send(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    uint8_t packet_len[4];
    WRITE_NET32(packet_len, 0, len);
    int ret = sendto(lan_play->f_fd, packet, len, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
    return ret == -1 ? 1 : 0; // 0 on success
}
