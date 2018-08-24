#ifndef _PACKET_H_
#define _PACKET_H_

#define ETHER_OFF_DST 0
#define ETHER_OFF_SRC 6
#define ETHER_OFF_TYPE 12
#define ETHER_OFF_END 14
#define ETHER_OFF_ARP 14
#define ETHER_OFF_IPV4 14
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_IPV4 0x0800
#define ETHER_HEADER_LEN 14

#define IPV4_PROTOCOL_ICMP 1
#define IPV4_HEADER_LEN 20

#define IPV4_OFF_VER_LEN 0
#define IPV4_OFF_DSCP_ECN 1
#define IPV4_OFF_TOTAL_LEN 2
#define IPV4_OFF_ID 4
#define IPV4_OFF_FLAGS_FRAG_OFFSET 6
#define IPV4_OFF_TTL 8
#define IPV4_OFF_PROTOCOL 9
#define IPV4_OFF_CHECKSUM 10
#define IPV4_OFF_SRC 12
#define IPV4_OFF_DST 16
#define IPV4_OFF_END 20

#define ARP_OFF_HARDWARE 0
#define ARP_OFF_PROTOCOL 2
#define ARP_OFF_HARDWARE_SIZE 4
#define ARP_OFF_PROTOCOL_SIZE 5
#define ARP_OFF_OPCODE 6
#define ARP_OFF_SENDER_MAC 8
#define ARP_OFF_SENDER_IP 14
#define ARP_OFF_TARGET_MAC 18
#define ARP_OFF_TARGET_IP 24
#define ARP_OFF_END 28
#define ARP_LEN 28
#define ARP_HARDTYPE_ETHER 1
#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY 2

struct ether_frame {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
    const u_char *payload;
};

struct ipv4 {
    const struct ether_frame *ether;
    uint8_t version;
    // unit: byte
    uint8_t header_len;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_len;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
    const u_char *payload;
};

struct arp {
    const struct ether_frame *ether;
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
    const u_char *payload;
};

struct icmp {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
    uint64_t timestamp;
    const u_char *payload;
};

struct payload {
    const u_char *ptr;
    uint16_t len;
    const struct payload *next;
};

int send_ether_ex(
    struct lan_play *arg,
    const void *dst,
    const void *src,
    uint16_t type,
    const struct payload *payload
);
int send_ether(
    struct lan_play *arg,
    const void *dst,
    uint16_t type,
    const struct payload *payload
);

#endif // _PACKET_H_
