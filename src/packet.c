#include "lan-play.h"

void print_packet(int id, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("id: %d\n", id);
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 

    int i;
    for (i=0; i<pkthdr->len; ++i) {
        printf(" %02x", packet[i]);
        if ( (i + 1) % 16 == 0 ) {
            printf("\n");
        }
    }

    printf("\n\n");
}

int send_packet(struct lan_play *arg, int size)
{
    return pcap_sendpacket(arg->dev, arg->buffer, size);
}

int process_ether(struct lan_play *arg, const u_char *packet)
{
    struct ether_frame ether;
    memcpy(ether.dst, packet + ETHER_OFF_DST, 6);
    memcpy(ether.src, packet + ETHER_OFF_SRC, 6);
    ether.type = READ_NET16(packet, ETHER_OFF_TYPE);
    ether.payload = packet + ETHER_OFF_END;

    switch (ether.type) {
        case ETHER_TYPE_ARP:
            return process_arp(arg, &ether);
        case ETHER_TYPE_IPV4:
            return process_ipv4(arg, &ether);
        default:
            return 0;
    }
}

void get_packet(struct lan_play *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    if (process_ether(arg, packet) == 0) {
        print_packet(++arg->id, pkthdr, packet);
    }
}
