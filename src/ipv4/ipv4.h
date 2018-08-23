#include "../lan-play.h"

int process_icmp(struct lan_play *arg, const struct ipv4 *ipv4);
int send_ipv4_ex(
    struct lan_play *arg,
    void *src,
    void *dst,
    uint8_t protocol,
    const u_char *payload,
    uint16_t length
);
int send_ipv4(
    struct lan_play *arg,
    void *dst,
    uint8_t protocol,
    const u_char *payload,
    uint16_t length
);
