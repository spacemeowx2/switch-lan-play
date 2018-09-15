#include "ipv4.h"

#define ENABLE_UDP_CHECKSUM 0

void parse_udp(const struct ipv4 *ipv4, struct udp *udp)
{
    const u_char *packet = ipv4->payload;

    udp->ipv4 = ipv4;
    udp->srcport = READ_NET16(packet, UDP_OFF_SRCPORT);
    udp->dstport = READ_NET16(packet, UDP_OFF_DSTPORT);
    udp->length = READ_NET16(packet, UDP_OFF_LENGTH);
    udp->checksum = READ_NET16(packet, UDP_OFF_CHECKSUM);
    udp->payload = packet + UDP_OFF_END;
}

int send_udp_ex(
    struct packet_ctx *self,
    const void *src,
    uint16_t srcport,
    const void *dst,
    uint16_t dstport,
    const struct payload *payload
)
{
    struct payload part;
    uint8_t buffer[UDP_OFF_END];
    uint8_t *buf = buffer;
    uint16_t udp_length = UDP_OFF_END + payload_total_len(payload);

    WRITE_NET16(buf, UDP_OFF_SRCPORT, srcport);
    WRITE_NET16(buf, UDP_OFF_DSTPORT, dstport);
    WRITE_NET16(buf, UDP_OFF_LENGTH, udp_length);
    WRITE_NET16(buf, UDP_OFF_CHECKSUM, 0);

    part.ptr = buffer;
    part.len = UDP_OFF_END;
    part.next = payload;

#if ENABLE_UDP_CHECKSUM
    uint8_t pseudo_header[IPV4P_OFF_END];
    struct payload pseudo_header_part;

    CPY_IPV4(pseudo_header + IPV4P_OFF_SRC, src);
    CPY_IPV4(pseudo_header + IPV4P_OFF_DST, dst);
    WRITE_NET8(pseudo_header, IPV4P_OFF_ZERO, 0);
    WRITE_NET8(pseudo_header, IPV4P_OFF_PROTOCOL, IPV4_PROTOCOL_UDP);
    WRITE_NET16(pseudo_header, IPV4P_OFF_LENGTH, udp_length);

    pseudo_header_part.ptr = pseudo_header;
    pseudo_header_part.len = IPV4P_OFF_END;
    pseudo_header_part.next = &part;

    // TODO: UDP checksum, it's incorrect :-(
    payload_print_hex(&pseudo_header_part);
    uint16_t checksum = calc_payload_checksum(&pseudo_header_part);
    WRITE_NET16(buf, UDP_OFF_CHECKSUM, checksum);
#endif

    return send_ipv4_ex(
        self,
        src,
        dst,
        IPV4_PROTOCOL_UDP,
        &part
    );
}
