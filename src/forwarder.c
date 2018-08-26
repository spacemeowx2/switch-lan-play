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
    uint8_t dst_mac[6];
    const uint8_t *dst = packet + IPV4_OFF_DST;
    struct payload part;

    printf("dst: ");
    PRINT_IP(dst);
    printf(" forwarder_process %d\n", len);
    if (lan_play->dev == NULL) {
        printf("not ready\n");
        return 0;
    }

    if (IS_BROADCAST(dst, lan_play->subnet_net, lan_play->subnet_mask)) {
        CPY_MAC(dst_mac, BROADCAST_MAC);
    } else if (!arp_get_mac_by_ip(lan_play, dst_mac, dst)) {
        return false;
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

void *forwarder_thread(void *p)
{
    uint8_t buffer[BUFFER_SIZE];
    uint32_t buf_len = 0;
    uint32_t recv_len = 0;
    int32_t wait_len = -1;
    int fromlen;
    struct lan_play *lan_play = (struct lan_play *)p;
    int fd = lan_play->f_fd;
    struct sockaddr_in *server_addr = &lan_play->server_addr;

    while (1) {
        fromlen = sizeof(*server_addr);
        recv_len = recvfrom(fd, buffer + buf_len, BUFFER_SIZE - buf_len, 0, (struct sockaddr *)server_addr, &fromlen);
        printf("recv_len %d\n", recv_len);
        if (recv_len == 0 || recv_len == -1) {
            break;
        }
        buf_len += recv_len;
        if (buf_len < 4) {
            continue;
        }
        if (wait_len == -1) {
            wait_len = READ_NET32(buffer, 0) + 4;
        }
        if (buf_len >= wait_len) {
            forwarder_process(lan_play, buffer + 4, wait_len - 4);
            printf("%d %d\n", buf_len, wait_len);
            memmove(buffer, buffer + wait_len, buf_len - wait_len);
            buf_len -= wait_len;
            wait_len = -1;
        }
    }

    fprintf(stderr, "Forwarder server disconnected\n");
    exit(1);

    return NULL;
}

int forwarder_send(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    struct sockaddr_in *server_addr = &lan_play->server_addr;
    printf("dst: ");
    PRINT_IP(dst_ip);
    printf(" forwarder_send %d\n", len);
    uint8_t packet_len[4];
    WRITE_NET32(packet_len, 0, len);
    send(lan_play->f_fd, packet_len, 4, 0);
    return sendto(lan_play->f_fd, packet, len, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
}
