#include "lan-play.h"

uint8_t NONE_IP[4] = {0, 0, 0, 0};

int process_arp(struct lan_play *arg, const struct ether_frame *ether)
{
    const u_char *packet = ether->payload;

    uint16_t hardware_type = READ_NET16(packet, ARP_OFF_HARDWARE);
    uint16_t protocol_type = READ_NET16(packet, ARP_OFF_PROTOCOL);
    uint16_t hardware_size = READ_NET8(packet, ARP_OFF_HARDWARE_SIZE);
    uint16_t protocol_size = READ_NET8(packet, ARP_OFF_PROTOCOL_SIZE);
    uint16_t opcode = READ_NET16(packet, ARP_OFF_OPCODE);

    uint8_t sender[4];
    uint8_t sender_mac[6];
    uint8_t target[4];
    char sender_ip[IP_STR_LEN];
    char target_ip[IP_STR_LEN];

    strcpy(sender_ip, ip2str(sender));
    strcpy(target_ip, ip2str(target));

    CPY_IPV4(sender, packet + ARP_OFF_SENDER_IP);
    CPY_MAC(sender_mac, packet + ARP_OFF_SENDER_MAC);
    CPY_IPV4(target, packet + ARP_OFF_TARGET_IP);

    // printf("[%d] ARP Sender: %s\n", arg->id, sender_ip);
    // printf("         Target: %s\n", target_ip);
    arp_set(arg, sender_mac, sender);

    if ((strcmp(SERVER_IP, target_ip) == 0) && (strcmp(CLIENT_IP, sender_ip) == 0)) {
        puts("Reply the ARP");

        void *buf = arg->buffer;
        CPY_MAC(buf + ETHER_OFF_DST, ether->src);
        CPY_MAC(buf + ETHER_OFF_SRC, arg->mac);
        WRITE_NET16(buf, ETHER_OFF_TYPE, ETHER_TYPE_ARP);
        buf += ETHER_OFF_ARP;
        memcpy(buf + ARP_OFF_HARDWARE, packet + ARP_OFF_HARDWARE, 2 + 2 + 1 + 1);
        WRITE_NET16(buf, ARP_OFF_OPCODE, 2); // reply

        CPY_MAC(buf + ARP_OFF_SENDER_MAC, arg->mac);
        CPY_IPV4(buf + ARP_OFF_SENDER_IP, target);
        CPY_MAC(buf + ARP_OFF_TARGET_MAC, ether->src);
        CPY_IPV4(buf + ARP_OFF_TARGET_IP, sender);

        // print_hex(arg->buffer, 42);

        int ret = send_packet(arg, 42);
        if (ret != 0) {
            fprintf(stderr, "Error sendPacket %d\n", ret);
        }
    }

    return 1;
}

void arp_list_init(struct arp_item *list)
{
    memset(list, 0, ARP_CACHE_LEN * sizeof(*list));
}

bool arp_get_mac_by_ip(struct lan_play *arg, void *mac, const void *ip)
{
    int i;
    struct arp_item *list = arg->arp_list;

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        if (CMP_IPV4(list[i].ip, ip)) {
            CPY_MAC(mac, list[i].mac);
            return true;
        }
    }

    puts("mac not found");
    return false;
}

bool arp_set(struct lan_play *arg, const void *mac, const void *ip)
{
    int i;
    struct arp_item *list = arg->arp_list;

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        if (CMP_IPV4(list[i].ip, NONE_IP) || CMP_IPV4(list[i].ip, ip)) {
            CPY_IPV4(list[i].ip, ip);
            CPY_MAC(list[i].mac, mac);
            return true;
        }
    }
    puts("set not found");

    return false;
}
