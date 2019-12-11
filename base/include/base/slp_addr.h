#ifndef SLP_ADDR_H
#define SLP_ADDR_H

#include <stdint.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

struct slp_addr_in {
	int8_t sin_len;
    uint16_t sin_family;
    union {
        struct sockaddr addr;
        struct sockaddr_in6 ipv6;
        struct sockaddr_in ipv4;
    } u;
};

#endif
