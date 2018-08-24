#include "ipv4.h"

int send_ipv4(
    struct lan_play *arg,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
)
{
    return send_ipv4_ex(
        arg,
        arg->ip,
        dst,
        protocol,
        payload
    );
}
int send_ipv4_ex(
    struct lan_play *arg,
    const void *src,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
)
{
    struct payload part;
    uint8_t dst_mac[6];
    uint8_t buffer[IPV4_HEADER_LEN];
    void *buf = buffer;
    uint8_t t;
    uint16_t tt;

    WRITE_NET8(buf, IPV4_OFF_VER_LEN, 0x45);
    WRITE_NET8(buf, IPV4_OFF_DSCP_ECN, 0x00);
    WRITE_NET16(buf, IPV4_OFF_TOTAL_LEN, IPV4_HEADER_LEN + payload->len);
    WRITE_NET16(buf, IPV4_OFF_ID, arg->identification++);
    WRITE_NET16(buf, IPV4_OFF_FLAGS_FRAG_OFFSET, 0);
    WRITE_NET8(buf, IPV4_OFF_TTL, 128);
    WRITE_NET8(buf, IPV4_OFF_PROTOCOL, protocol);
    WRITE_NET16(buf, IPV4_OFF_CHECKSUM, 0x0000);

    memcpy(buf + IPV4_OFF_SRC, src, 4);
    memcpy(buf + IPV4_OFF_DST, dst, 4);

    uint16_t checksum = calc_checksum(buffer, IPV4_HEADER_LEN);
    WRITE_NET16(buf, IPV4_OFF_CHECKSUM, checksum);

    part.ptr = buffer;
    part.len = IPV4_HEADER_LEN;
    part.next = payload;
    
    if (!arp_get_mac_by_ip(arg, dst_mac, dst)) {
        return false;
    }

    return send_ether(
        arg,
        dst_mac,
        ETHER_TYPE_IPV4,
        &part
    );;
}

void parse_ipv4(const struct ether_frame *ether, struct ipv4 *ipv4)
{
    const u_char *packet = ether->payload;
    uint8_t t;
    uint16_t tt;

    ipv4->ether = ether;
    t = READ_NET8(packet, IPV4_OFF_VER_LEN);
    ipv4->version = t >> 4;
    ipv4->header_len = (t & 0xF) * 4;
    t = READ_NET8(packet, IPV4_OFF_DSCP_ECN);
    ipv4->dscp = t >> 2;
    ipv4->ecn = t & 3; // 0b11
    ipv4->total_len = READ_NET16(packet, IPV4_OFF_TOTAL_LEN);
    ipv4->identification = READ_NET16(packet, IPV4_OFF_ID);
    tt = READ_NET16(packet, IPV4_OFF_FLAGS_FRAG_OFFSET);
    ipv4->flags = tt >> 13;
    ipv4->fragment_offset = tt & 0x1fff;
    ipv4->ttl = READ_NET8(packet, IPV4_OFF_TTL);
    ipv4->protocol = READ_NET8(packet, IPV4_OFF_PROTOCOL);
    ipv4->checksum = READ_NET16(packet, IPV4_OFF_PROTOCOL);
    CPY_IPV4(ipv4->src, packet, IPV4_OFF_SRC);
    CPY_IPV4(ipv4->dst, packet, IPV4_OFF_DST);
    ipv4->payload = packet + ipv4->header_len;
}

int process_ipv4(struct lan_play *arg, const struct ether_frame *ether)
{
    struct ipv4 ipv4;
    parse_ipv4(ether, &ipv4);

    switch (ipv4.protocol) {
        case IPV4_PROTOCOL_ICMP:
            return process_icmp(arg, &ipv4);
    }

    return 1;
}

uint16_t calc_checksum(const u_char *buffer, int len)
{
    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)buffer;
    while (len > 1) {
        sum += ntohs(*buf++);
        len -= sizeof(uint16_t);
    }
    if (len) {
        sum += *(uint8_t *)buf; 
    }
    while (sum > 0xffff) {
        sum -= 0xffff;
    }
    return ~sum;
}
