#include "lan-play.h"

struct IPv4 {
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags;
    uint8_t ttl;
    uint8_t protocol;
    uint8_t src[4];
    uint8_t dst[4];
};

uint16_t calc_checksum(const u_char *packet, int len);

int ipv4_get_header_len(const u_char *packet)
{
    uint8_t ver_len = READ_NET8(packet, IPV4_OFF_VER_LEN);
    return (ver_len & 0xF) * 4;
}

int fill_ipv4(struct LanPlay *arg, const u_char *packet, const struct IPv4 *ipv4)
{
    const void *dst_mac = packet + ETHER_OFF_SRC;
    void *buf = arg->buffer;
    memcpy(buf + ETHER_OFF_DST, dst_mac, 6);
    memcpy(buf + ETHER_OFF_SRC, arg->mac, 6);
    WRITE_NET16(buf, ETHER_OFF_TYPE, ETHER_TYPE_IPV4);

    WRITE_NET8(buf, IPV4_OFF_VER_LEN, 0x45);
    WRITE_NET8(buf, IPV4_OFF_DSF, 0x00);
    WRITE_NET16(buf, IPV4_OFF_TOTAL_LEN, ipv4->total_len);
    WRITE_NET16(buf, IPV4_OFF_ID, ipv4->identification);
    WRITE_NET16(buf, IPV4_OFF_FLAGS, ipv4->flags);
    WRITE_NET8(buf, IPV4_OFF_TTL, ipv4->ttl);
    WRITE_NET8(buf, IPV4_OFF_PROTOCOL, ipv4->protocol);
    WRITE_NET16(buf, IPV4_OFF_CHECKSUM, 0x0000);

    memcpy(buf + IPV4_OFF_SRC, ipv4->src, 4);
    memcpy(buf + IPV4_OFF_DST, ipv4->dst, 4);

    uint16_t checksum = calc_checksum(buf + ETHER_OFF_IPV4, IPV4_HEADER_LEN);
    WRITE_NET16(buf, IPV4_OFF_CHECKSUM, checksum);

}

int process_icmp(struct LanPlay *arg, const u_char *packet, const struct IPv4 *ipv4)
{
    void *buf = arg->buffer;
    struct IPv4 header;
    header.total_len = ipv4->total_len;
    header.identification = arg->identification++;
    header.flags = 0x0000;
    header.ttl = 128;
    header.protocol = IPV4_PROTOCOL_ICMP;
    memcpy(header.src, ipv4->dst, 4);
    memcpy(header.dst, ipv4->src, 4);
    fill_ipv4(arg, packet, &header);

    int icmp_len = ipv4->total_len - ipv4_get_header_len(packet);
    memcpy(buf + IPV4_OFF_END, packet + IPV4_OFF_END, icmp_len);
    WRITE_NET8(buf, IPV4_OFF_END, 0);
    WRITE_NET16(buf, IPV4_OFF_END + 2, 0x0000); // checksum
    uint16_t sum = calc_checksum(buf + IPV4_OFF_END, icmp_len);
    WRITE_NET16(buf, IPV4_OFF_END + 2, sum);

    int ret = sendPacket(arg, header.total_len + ETHER_HEADER_LEN);
    printf("sendPacket %d\n", ret);
}

int processIPv4(struct LanPlay *arg, const u_char *packet)
{
    struct IPv4 ipv4;

    ipv4.total_len = READ_NET16(packet, IPV4_OFF_TOTAL_LEN);
    ipv4.identification = READ_NET16(packet, IPV4_OFF_ID);
    ipv4.flags = READ_NET16(packet, IPV4_OFF_FLAGS);
    ipv4.ttl = READ_NET8(packet, IPV4_OFF_TTL);
    ipv4.protocol = READ_NET8(packet, IPV4_OFF_PROTOCOL);
    FILL_IPV4(ipv4.src, packet, IPV4_OFF_SRC);
    FILL_IPV4(ipv4.dst, packet, IPV4_OFF_DST);
    switch (ipv4.protocol) {
        case IPV4_PROTOCOL_ICMP:
            return process_icmp(arg, packet, &ipv4);
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
