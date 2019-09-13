#ifndef SLP_ADDR_H
#define SLP_ADDR_H

#include <stdint.h>
#ifdef __WIN32
#include <ws2tcpip.h>
typedef u_short sa_family_t
#else
#include <netinet/in.h>
#endif

struct slp_addr_in {
	int8_t sin_len;
    sa_family_t sin_family;
    union {
        struct sockaddr addr;
        struct sockaddr_in6 ipv6;
        struct sockaddr_in ipv4;
    } u;
};

#endif
