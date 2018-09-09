#include "ipv4.h"

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
