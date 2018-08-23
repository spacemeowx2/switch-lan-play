#include "ipv4.h"

int process_icmp(struct lan_play *arg, const struct ipv4 *ipv4)
{
    uint8_t payload[BUFFER_SIZE];
    void *buf = arg->buffer;

    int icmp_len = ipv4->total_len - ipv4->header_len;
    memcpy(payload, ipv4->payload, icmp_len);
    WRITE_NET8(payload, IPV4_OFF_END, 0); // response
    WRITE_NET16(payload, IPV4_OFF_END + 2, 0x0000); // checksum
    uint16_t sum = calc_checksum(payload, icmp_len);
    WRITE_NET16(payload, IPV4_OFF_END + 2, sum);

    int ret = send_ipv4(
        arg,
        ipv4->src,
        IPV4_PROTOCOL_ICMP,
        payload,
        icmp_len
    )
    if (ret != 0) {
        fprintf(stderr, "Error send_ipv4 %d\n", ret);
    }
    return 1;
}
