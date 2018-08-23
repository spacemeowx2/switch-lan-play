#include "lan-play.h"

void printPacket(int id, const struct pcap_pkthdr *pkthdr, const u_char *packet)
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

int sendPacket(struct LanPlay *arg, int size)
{
    return pcap_sendpacket(arg->dev, arg->buffer, size);
}

int process(struct LanPlay *arg, const u_char *packet)
{
    uint16_t type = READ_NET16(packet, ETHER_OFF_TYPE);
    // printf("Ether type: %x\n", type);
    switch (type) {
        case ETHER_TYPE_ARP:
            return processARP(arg, packet);
        case ETHER_TYPE_IPV4:
            return processIPv4(arg, packet);
        default:
            return 0;
    }
}

void getPacket(struct LanPlay *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    if (process(arg, packet) == 0) {
        printPacket(++arg->id, pkthdr, packet);
    }
}
