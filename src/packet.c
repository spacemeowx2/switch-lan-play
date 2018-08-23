#include "lan-play.h"

int send_payloads(
    struct lan_play *arg,
    const struct payload *payload
)
{
    uint8_t *buf = arg->buffer;
    const struct payload *part = payload;
    uint16_t total_len = 0;

    while (part) {
        memcpy(buf, part->ptr, part->len);
        buf += part->len;
        part = part->next;
        total_len += part->len;
    }

    return send_packet(arg, total_len);
}

int send_ether_ex(
    struct lan_play *arg,
    void *dst,
    void *src,
    uint16_t type,
    const struct payload *payload
)
{
    uint8_t buffer[ETHER_HEADER_LEN];
    struct payload part;
    
    part.ptr = buffer;
    part.len = ETHER_HEADER_LEN;
    part.next = payload;

    memcpy(buffer + ETHER_OFF_DST, dst, 6);
    memcpy(buffer + ETHER_OFF_SRC, src, 6);
    WRITE_NET16(buffer, ETHER_OFF_TYPE, type);

    return send_payloads(arg, &part);
}
int send_ether(
    struct lan_play *arg,
    void *dst,
    uint16_t type,
    const struct payload *payload
)
{
    return send_ether_ex(
        arg,
        dst,
        arg->mac,
        type,
        payload
    );
}

void print_packet(int id, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("id: %d\n", id);
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 

    int i;
    for (i=0; i<pkthdr->len; ++i) {
        printf(" %02x", packet[i]);
        if ( (i + 1) % 16 == 0 ) {
            printf("\n");
        }
    }

    printf("\n\n");
}

int send_packet(struct lan_play *arg, int size)
{
    return pcap_sendpacket(arg->dev, arg->buffer, size);
}

int process_ether(struct lan_play *arg, const u_char *packet)
{
    struct ether_frame ether;
    memcpy(ether.dst, packet + ETHER_OFF_DST, 6);
    memcpy(ether.src, packet + ETHER_OFF_SRC, 6);
    ether.type = READ_NET16(packet, ETHER_OFF_TYPE);
    ether.payload = packet + ETHER_OFF_END;

    switch (ether.type) {
        case ETHER_TYPE_ARP:
            return process_arp(arg, &ether);
        case ETHER_TYPE_IPV4:
            return process_ipv4(arg, &ether);
        default:
            return 0;
    }
}

void get_packet(struct lan_play *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    if (process_ether(arg, packet) == 0) {
        print_packet(++arg->id, pkthdr, packet);
    }
}
