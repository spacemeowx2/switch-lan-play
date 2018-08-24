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
        total_len += part->len;

        part = part->next;
    }

    // print_hex(arg->buffer, total_len);
    // printf("total len %d\n", total_len);
    return send_packet(arg, total_len);
}

int send_ether_ex(
    struct lan_play *arg,
    const void *dst,
    const void *src,
    uint16_t type,
    const struct payload *payload
)
{
    uint8_t buffer[ETHER_HEADER_LEN];
    struct payload part;
    
    part.ptr = buffer;
    part.len = ETHER_HEADER_LEN;
    part.next = payload;

    CPY_MAC(buffer + ETHER_OFF_DST, dst);
    CPY_MAC(buffer + ETHER_OFF_SRC, src);
    WRITE_NET16(buffer, ETHER_OFF_TYPE, type);

    return send_payloads(arg, &part);
}
int send_ether(
    struct lan_play *arg,
    const void *dst,
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

    uint32_t i;
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

void parse_ether(const u_char *packet, struct ether_frame *ether)
{
    CPY_MAC(ether->dst, packet + ETHER_OFF_DST);
    CPY_MAC(ether->src, packet + ETHER_OFF_SRC);
    ether->type = READ_NET16(packet, ETHER_OFF_TYPE);
    ether->payload = packet + ETHER_OFF_END;
}

int process_ether(struct lan_play *arg, const u_char *packet)
{
    struct ether_frame ether;
    parse_ether(packet, &ether);

    if (CMP_MAC(ether.src, arg->mac)) {
        return 1;
    }

    switch (ether.type) {
        case ETHER_TYPE_ARP:
            return process_arp(arg, &ether);
        case ETHER_TYPE_IPV4:
            return process_ipv4(arg, &ether);
        default:
            return 1; // just ignore them
    }
}

void get_packet(struct lan_play *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    if (process_ether(arg, packet) == 0) {
        print_packet(++arg->id, pkthdr, packet);
    }
}
