#ifndef _HELPER_H_
#define _HELPER_H_

#include <arpa/inet.h>
#define READ_NET8(packet, offset) (*(uint8_t*)((uint8_t*)packet + offset))
#define READ_NET16(packet, offset) ntohs(*(uint16_t*)((uint8_t*)packet + offset))
#define WRITE_NET8(packet, offset, v) (*(uint8_t*)((uint8_t*)packet + offset) = v)
#define WRITE_NET16(packet, offset, v) (*(uint16_t*)((uint8_t*)packet + offset) = htons(v))
#define FILL_IPV4(r, packet, offset) do { \
    WRITE_NET8(r, 0, READ_NET8(packet, offset + 0)); \
    WRITE_NET8(r, 1, READ_NET8(packet, offset + 1)); \
    WRITE_NET8(r, 2, READ_NET8(packet, offset + 2)); \
    WRITE_NET8(r, 3, READ_NET8(packet, offset + 3)); \
} while(0)
const char *ip2str(void *ip);
void *str2ip(const char *ip);
#endif // _HELPER_H_
