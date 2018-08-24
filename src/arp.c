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

    CPY_IPV4(sender, packet, ARP_OFF_SENDER_IP);
    memcpy(sender_mac, packet + ARP_OFF_SENDER_MAC, 6);
    CPY_IPV4(target, packet, ARP_OFF_TARGET_IP);

    // printf("[%d] ARP Sender: %s\n", arg->id, sender_ip);
    // printf("         Target: %s\n", target_ip);
    arp_set(arg, sender_mac, sender);

    if ((strcmp(SERVER_IP, target_ip) == 0) && (strcmp(CLIENT_IP, sender_ip) == 0)) {
        puts("Reply the ARP");

        void *buf = arg->buffer;
        memcpy(buf + ETHER_OFF_DST, ether->src, 6);
        memcpy(buf + ETHER_OFF_SRC, arg->mac, 6);
        WRITE_NET16(buf, ETHER_OFF_TYPE, ETHER_TYPE_ARP);
        buf += ETHER_OFF_ARP;
        memcpy(buf + ARP_OFF_HARDWARE, packet + ARP_OFF_HARDWARE, 2 + 2 + 1 + 1);
        WRITE_NET16(buf, ARP_OFF_OPCODE, 2); // reply

        memcpy(buf + ARP_OFF_SENDER_MAC, arg->mac, 6);
        memcpy(buf + ARP_OFF_SENDER_IP, target, 4);
        memcpy(buf + ARP_OFF_TARGET_MAC, ether->src, 6);
        memcpy(buf + ARP_OFF_TARGET_IP, sender, 4);

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

int arp_get_mac_by_ip(struct lan_play *arg, void *mac, const void *ip)
{
    int i;
    struct arp_item *list = arg->arp_list;

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        if (memcmp(list[i].ip, ip, 4) == 0) {
            memcpy(mac, list[i].mac, 6);
            return true;
        }
    }

    puts("mac not found");
    return false;
}
int arp_set(struct lan_play *arg, const void *mac, const void *ip)
{
    int i;
    struct arp_item *list = arg->arp_list;

    // puts("arp set");
    // print_hex(mac, 6);
    // print_hex(ip, 4);
    // puts("");

    for (i = 0; i < ARP_CACHE_LEN; i++) {
        if (memcmp(list[i].ip, NONE_IP, 4) == 0) {
            memcpy(list[i].ip, ip, 4);
            memcpy(list[i].mac, mac, 6);
            return true;
        }
    }
    puts("set not found");

    return false;
}
