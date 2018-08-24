#ifndef _ARP_H_
#define _ARP_H_

#include <stdint.h>

#define ARP_CACHE_LEN 100

struct arp_item {
    uint8_t ip[4];
    uint8_t mac[6];
    time_t expire_at;
};

void arp_list_init(struct arp_item *list);
bool arp_get_mac_by_ip(struct lan_play *arg, void *mac, const void *ip);
bool arp_set(struct lan_play *arg, const void *mac, const void *ip);

#endif // _ARP_H_
