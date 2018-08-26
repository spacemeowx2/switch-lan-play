#include "lan-play.h"

void forwarder_init(struct lan_play *lan_play)
{
    int ret;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server_net;
    struct sockaddr_in server_addr;

    server_net = gethostbyname(SERVER_ADDR);
    if (server_net == NULL) {
        fprintf(stderr, "Error gethostbyname %s\n", strerror(errno));
        exit(1);
    }
    printf("%p %x\n", server_net, *(uint32_t*)server_net->h_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = *((struct in_addr *)server_net->h_addr);
    server_addr.sin_port = htons(SERVER_PORT);

    ret = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret != 0) {
        fprintf(stderr, "Error connect %d\n", ret);
        exit(1);
    }
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

    if (!arp_get_mac_by_ip(lan_play, dst_mac, dst)) {
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
    struct lan_play *lan_play = (struct lan_play *)p;
    int fd = lan_play->f_fd;

    while (recv(fd, buffer + buf_len, BUFFER_SIZE - buf_len, 0) != 0) {
        if (buf_len >= 4) {
            uint32_t packet_len = READ_NET32(buffer, 0);
            if (buf_len >= packet_len) {
                forwarder_process(lan_play, buffer + 4, packet_len);
            }
        }
    }

    fprintf(stderr, "Forwarder server disconnected\n");
    exit(1);

    return NULL;
}

int forwarder_send(struct lan_play *lan_play, void *dst_ip, const void *packet, uint16_t len)
{
    uint8_t packet_len[4];
    WRITE_NET32(packet_len, 0, len);
    send(lan_play->f_fd, packet_len, 4, 0);
    return send(lan_play->f_fd, packet, len, 0);
}
