#ifndef _HELPER_H_
#define _HELPER_H_

#include <pcap.h>
#include <unistd.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
// https://linux.die.net/man/2/sendto
struct iovec {
    size_t iov_len;
    void *iov_base;
};
struct msghdr {
    void         *msg_name;       /* optional address */
    socklen_t     msg_namelen;    /* size of address */
    struct iovec *msg_iov;        /* scatter/gather array */
    size_t        msg_iovlen;     /* # elements in msg_iov */
    void         *msg_control;    /* ancillary data, see below */
    size_t        msg_controllen; /* ancillary data buffer len */
    int           msg_flags;      /* flags on received message */
};
ssize_t sendmsg(int s, const struct msghdr *msg, int flags);
#else
#include <arpa/inet.h>
#include <netdb.h>
#endif
#define LMIN(a, b) ((a) < (b) ? (a) : (b))
#define READ_NET8(packet, offset) (*(uint8_t*)((uint8_t*)packet + offset))
#define READ_NET16(packet, offset) ntohs(*(uint16_t*)((uint8_t*)packet + offset))
#define READ_NET32(packet, offset) ntohl(*(uint32_t*)((uint8_t*)packet + offset))
#define WRITE_NET8(packet, offset, v) (*(uint8_t*)((uint8_t*)packet + offset) = v)
#define WRITE_NET16(packet, offset, v) (*(uint16_t*)((uint8_t*)packet + offset) = htons(v))
#define WRITE_NET32(packet, offset, v) (*(uint32_t*)((uint8_t*)packet + offset) = htonl(v))
#define CPY_IPV4(ip1, ip2) (memcpy(ip1, ip2, 4))
#define CPY_MAC(mac1, mac2) (memcpy(mac1, mac2, 6))
#define CMP_IPV4(ip1, ip2) (memcmp(ip1, ip2, 4) == 0)
#define CMP_MAC(mac1, mac2) (memcmp(mac1, mac2, 4) == 0)
#define IS_SUBNET(ip, net, mask) ( ((*(uint32_t*)ip) & (*(uint32_t*)mask)) == *(uint32_t*)net )
#define IS_BROADCAST(ip, net, mask) ( ((*(uint32_t*)net) | ( ~ *(uint32_t*)mask)) == *(uint32_t*)ip )
#define PRINT_IP(ip) printf("%d.%d.%d.%d", *(uint8_t*)(ip), *(uint8_t*)((uint8_t*)ip + 1), *(uint8_t*)((uint8_t*)ip + 2), *(uint8_t*)((uint8_t*)ip + 3))
#define PRINT_MAC(mac) printf("%x:%x:%x:%x:%x:%x", *(uint8_t*)(mac), *(uint8_t*)((uint8_t*)mac + 1), *(uint8_t*)((uint8_t*)mac + 2), *(uint8_t*)((uint8_t*)mac + 3), *(uint8_t*)((uint8_t*)mac + 4), *(uint8_t*)((uint8_t*)mac + 5))

const char *ip2str(void *ip);
void *str2ip(const char *ip);
void print_hex(const void *buf, int len);
int set_immediate_mode(pcap_t *p);
int get_mac_address(pcap_if_t *d, pcap_t *p, u_char mac_addr[6]);
int parse_addr(const char *str, struct sockaddr_in *addr);
#endif // _HELPER_H_
