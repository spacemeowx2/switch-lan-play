#ifndef _ARP_H_
#define _ARP_H_

#include <stdint.h>
#include <stdbool.h>

#define ARP_CACHE_LEN 100

struct arp_item {
    uint8_t ip[4];
    uint8_t mac[6];
    time_t expire_at;
};

typedef int (*arp_for_each_cb)(void *userdata, const struct arp_item *item);

struct packet_ctx;
void arp_list_init(struct arp_item *list);
bool arp_get_mac_by_ip(struct packet_ctx *arg, void *mac, const void *ip);
bool arp_has_ip(struct packet_ctx *arg, const void *ip);
bool arp_set(struct packet_ctx *arg, const void *mac, const void *ip);
void arp_for_each(struct packet_ctx *self, void *userdata, arp_for_each_cb cb);

#endif // _ARP_H_
