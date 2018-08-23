#include "lan-play.h"

int processARP(struct LanPlay *arg, const u_char *packet)
{
    uint16_t hardware_type = READ_NET16(packet, ARP_OFF_HARDWARE);
    uint16_t protocol_type = READ_NET16(packet, ARP_OFF_PROTOCOL);
    uint16_t hardware_size = READ_NET8(packet, ARP_OFF_HARDWARE_SIZE);
    uint16_t protocol_size = READ_NET8(packet, ARP_OFF_PROTOCOL_SIZE);
    uint16_t opcode = READ_NET16(packet, ARP_OFF_OPCODE);

    uint8_t sender[4];
    uint8_t target[4];
    char sender_ip[IP_STR_LEN];
    char target_ip[IP_STR_LEN];

    strcpy(sender_ip, ip2str(sender));
    strcpy(target_ip, ip2str(target));

    FILL_IPV4(sender, packet, ARP_OFF_SENDER_IP);
    FILL_IPV4(target, packet, ARP_OFF_TARGET_IP);

    // printf("[%d] ARP Sender: %s\n", arg->id, sender_ip);
    // printf("         Target: %s\n", target_ip);

    if ((strcmp(SERVER_IP, target_ip) == 0) && (strcmp(CLIENT_IP, sender_ip) == 0)) {
        puts("Reply the ARP");

        const void *dst_mac = packet + ETHER_OFF_SRC;
        void *buf = arg->buffer;
        memcpy(buf + ETHER_OFF_DST, dst_mac, 6);
        memcpy(buf + ETHER_OFF_SRC, arg->mac, 6);
        WRITE_NET16(buf, ETHER_OFF_TYPE, ETHER_TYPE_ARP);
        memcpy(buf + ARP_OFF_HARDWARE, packet + ARP_OFF_HARDWARE, 2 + 2 + 1 + 1);
        WRITE_NET16(buf, ARP_OFF_OPCODE, 2); // reply

        memcpy(buf + ARP_OFF_SENDER_MAC, arg->mac, 6);
        memcpy(buf + ARP_OFF_SENDER_IP, target, 4);
        memcpy(buf + ARP_OFF_TARGET_MAC, dst_mac, 6);
        memcpy(buf + ARP_OFF_TARGET_IP, sender, 4);

        int ret = sendPacket(arg, 42);
        printf("sendPacket %d\n", ret);
    }

    return 1;
}
