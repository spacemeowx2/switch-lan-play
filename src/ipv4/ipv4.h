#include "../lan-play.h"

void parse_ipv4(const struct ether_frame *ether, struct ipv4 *ipv4);
void parse_udp(const struct ipv4 *ipv4, struct udp *udp);
int process_icmp(struct packet_ctx *arg, const struct ipv4 *ipv4);
int send_ipv4_ex(
    struct packet_ctx *arg,
    const void *src,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
);
int send_ipv4(
    struct packet_ctx *arg,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
);
int send_udp_ex(
    struct packet_ctx *self,
    const void *src,
    uint16_t srcport,
    const void *dst,
    uint16_t dstport,
    const struct payload *payload
);
uint16_t calc_checksum(const u_char *packet, int len);
uint16_t calc_payload_checksum(const struct payload *payload);
