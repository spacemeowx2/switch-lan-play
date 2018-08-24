#ifndef _HELPER_H_
#define _HELPER_H_

#include <pcap.h>
#if defined(_WIN32)
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define READ_NET8(packet, offset) (*(uint8_t*)((uint8_t*)packet + offset))
#define READ_NET16(packet, offset) ntohs(*(uint16_t*)((uint8_t*)packet + offset))
#define WRITE_NET8(packet, offset, v) (*(uint8_t*)((uint8_t*)packet + offset) = v)
#define WRITE_NET16(packet, offset, v) (*(uint16_t*)((uint8_t*)packet + offset) = htons(v))
#define CPY_IPV4(ip1, ip2) (memcpy(ip1, ip2, 4))
#define CPY_MAC(mac1, mac2) (memcpy(mac1, mac2, 6))
#define CMP_IPV4(ip1, ip2) (memcmp(ip1, ip2, 4) == 0)
#define CMP_MAC(mac1, mac2) (memcmp(mac1, mac2, 4) == 0)
#define IS_SUBNET(ip, net, mask) ( (*(uint32_t*)ip) & mask == *(uint32_t*)net )
#define PRINT_IP(ip) printf("%d.%d.%d.%d", *(uint8_t*)(ip), *(uint8_t*)(ip + 1), *(uint8_t*)(ip + 2), *(uint8_t*)(ip + 3))
#define PRINT_MAC(mac) printf("%x:%x:%x:%x:%x:%x", *(uint8_t*)(mac), *(uint8_t*)(mac + 1), *(uint8_t*)(mac + 2), *(uint8_t*)(mac + 3), *(uint8_t*)(mac + 4), *(uint8_t*)(mac + 5))
const char *ip2str(void *ip);
void *str2ip(const char *ip);
void print_hex(const void *buf, int len);
#if __APPLE__
int set_immediate_mode(int fd);
#endif
#if defined(_WIN32)
int get_mac_address(pcap_if_t *d, u_char mac_addr[6]);
#endif
#endif // _HELPER_H_
