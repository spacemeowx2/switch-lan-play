#include "../lan-play.h"

void parse_ipv4(const struct ether_frame *ether, struct ipv4 *ipv4);
int process_icmp(struct lan_play *arg, const struct ipv4 *ipv4);
int send_ipv4_ex(
    struct lan_play *arg,
    const void *src,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
);
int send_ipv4(
    struct lan_play *arg,
    const void *dst,
    uint8_t protocol,
    const struct payload *payload
);
uint16_t calc_checksum(const u_char *packet, int len);
