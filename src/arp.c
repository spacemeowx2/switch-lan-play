#include "lan-play.h"

uint8_t NONE_IP[4] = {0, 0, 0, 0};
uint8_t NONE_MAC[6] = {0, 0, 0, 0, 0, 0};
uint8_t BROADCASE_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void parse_arp(const struct ether_frame *ether, struct arp *arp)
{
    const u_char *packet = ether->payload;
    arp->hardware_type = READ_NET16(packet, ARP_OFF_HARDWARE);
    arp->protocol_type = READ_NET16(packet, ARP_OFF_PROTOCOL);
    arp->hardware_size = READ_NET8(packet, ARP_OFF_HARDWARE_SIZE);
    arp->protocol_size = READ_NET8(packet, ARP_OFF_PROTOCOL_SIZE);
    arp->opcode = READ_NET16(packet, ARP_OFF_OPCODE);

    CPY_MAC(arp->sender_mac, packet + ARP_OFF_SENDER_MAC);
    CPY_IPV4(arp->sender_ip, packet + ARP_OFF_SENDER_IP);
    CPY_MAC(arp->target_mac, packet + ARP_OFF_TARGET_MAC);
    CPY_IPV4(arp->target_ip, packet + ARP_OFF_TARGET_IP);

    arp->payload = NULL;
}

int send_arp_ex(
    struct packet_ctx *self,
    const void *dst_mac,
    uint8_t opcode,
    const void *sender_mac,
    const void *sender_ip,
    const void *target_mac,
    const void *target_ip
)
{
    uint8_t buffer[ARP_LEN];
    struct payload part;

    WRITE_NET16(buffer, ARP_OFF_HARDWARE, ARP_HARDTYPE_ETHER);
    WRITE_NET16(buffer, ARP_OFF_PROTOCOL, ETHER_TYPE_IPV4);
    WRITE_NET8(buffer, ARP_OFF_HARDWARE_SIZE, 6);
    WRITE_NET8(buffer, ARP_OFF_PROTOCOL_SIZE, 4);
    WRITE_NET16(buffer, ARP_OFF_OPCODE, opcode);

    CPY_MAC(buffer + ARP_OFF_SENDER_MAC, sender_mac);
    CPY_IPV4(buffer + ARP_OFF_SENDER_IP, sender_ip);
    CPY_MAC(buffer + ARP_OFF_TARGET_MAC, target_mac);
    CPY_IPV4(buffer + ARP_OFF_TARGET_IP, target_ip);

    part.ptr = buffer;
    part.len = ARP_LEN;
    part.next = NULL;

    return send_ether(
        self,
        dst_mac,
        ETHER_TYPE_ARP,
        &part
    );
}

int send_arp(
    struct packet_ctx *self,
    uint8_t opcode,
    const void *sender_mac,
    const void *sender_ip,
    const void *target_mac,
    const void *target_ip
)
{
    return send_arp_ex(
        self,
        target_mac,
        opcode,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip
    );
}

int send_arp_request(
    struct packet_ctx *self,
    const void *target_ip
)
{
    return send_arp_ex(
        self,
        BROADCASE_MAC,
        ARP_OPCODE_REQUEST,
        self->mac,
        self->ip,
        NONE_MAC,
        target_ip
    );
}

int arp_request(struct packet_ctx *self, const struct arp *arp)
{
    if (IS_SUBNET(arp->target_ip, self->subnet_net, self->subnet_mask)) {
        if (CMP_IPV4(arp->target_ip, arp->sender_ip)) {
            return 0;
        }
        if (CMP_IPV4(arp->sender_ip, NONE_IP)) {
            return 0;
        }
        if (arp_has_ip(self, arp->target_ip)) {
            return 0;
        }
        return send_arp(
            self,
            ARP_OPCODE_REPLY,
            self->mac,
            arp->target_ip,
            arp->sender_mac,
            arp->sender_ip
        );
    }
    return 0;
}

int arp_reply(struct packet_ctx *self, const struct arp *arp)
{
    return 0;
}

int process_arp(struct packet_ctx *self, const struct ether_frame *ether)
{
    struct arp arp;
    parse_arp(ether, &arp);

    if (
        arp.hardware_type != ARP_HARDTYPE_ETHER
        || arp.protocol_type != ETHER_TYPE_IPV4
        || arp.hardware_size != 6
        || arp.protocol_size != 4
    ) {
        printf("Unknown hardware or protocol:\n");
        printf("hardware_type: %d protocol_type: %x\n", arp.hardware_type, arp.protocol_type);
        printf("hardware_size: %d protocol_size: %d\n", arp.hardware_size, arp.protocol_size);
        return -1;
    }

    arp_set(self, arp.sender_mac, arp.sender_ip);

    switch (arp.opcode) {
        case ARP_OPCODE_REQUEST:
            return arp_request(self, &arp);
        case ARP_OPCODE_REPLY:
            return arp_reply(self, &arp);
    }

    return -1;
}

void arp_list_init(struct arp_item *list)
{
    memset(list, 0, ARP_CACHE_LEN * sizeof(*list));
}

bool arp_has_ip(struct packet_ctx *self, const void *ip)
{
    int i;
    struct arp_item *list = self->arp_list;
    struct arp_item *item;
    time_t now = time(NULL);

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        item = &list[i];
        if (CMP_IPV4(item->ip, ip) && (item->expire_at > now)) {
            return true;
        }
    }

    return false;
}

bool arp_get_mac_by_ip(struct packet_ctx *self, void *mac, const void *ip)
{
    int i;
    struct arp_item *list = self->arp_list;
    struct arp_item *item;
    time_t now = time(NULL);

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        item = &list[i];
        if (CMP_IPV4(item->ip, ip) && (item->expire_at > now)) {
            CPY_MAC(mac, item->mac);
            return true;
        }
    }

    int ret = send_arp_request(self, ip);
    printf("arp_get_mac_by_ip not found %d ", ret);
    PRINT_IP(ip);
    putchar('\n');
    return false;
}

bool arp_set(struct packet_ctx *self, const void *mac, const void *ip)
{
    int i;
    struct arp_item *list = self->arp_list;
    struct arp_item *item;
    time_t now = time(NULL);

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        item = &list[i];
        if (CMP_IPV4(item->ip, NONE_IP) || CMP_IPV4(item->ip, ip) || item->expire_at < now) {
            CPY_IPV4(item->ip, ip);
            CPY_MAC(item->mac, mac);
            item->expire_at = now + self->arp_ttl;
            return true;
        }
    }
    puts("set not found");

    return false;
}
