#ifndef _ARP_H_
#define _ARP_H_

#include <stdint.h>

#define ARP_CACHE_LEN 100

struct arp_item {
    uint8_t ip[4];
    uint8_t mac[6];
};

void arp_list_init(struct arp_item *list);
int arp_get_mac_by_ip(void *mac, const void *ip);
int arp_set(const void *mac, const void *ip);

#endif // _ARP_H_
