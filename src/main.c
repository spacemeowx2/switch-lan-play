#include "lan-play.h"

uint8_t SEND_BUFFER[BUFFER_SIZE];

void set_filter(pcap_t *dev)
{
    char filter[100];
    static struct bpf_program bpf;
    snprintf(filter, sizeof(filter), "net %s %s", SUBNET_NET, SUBNET_MASK);
    pcap_compile(dev, &bpf, filter, 1, 0);
    pcap_setfilter(dev, &bpf);
}

void init_lan_play(struct lan_play *lan_play, pcap_t *dev)
{
    lan_play->dev = dev;
    lan_play->id = 0;
    lan_play->buffer = SEND_BUFFER;
    lan_play->identification = 0;
    CPY_IPV4(lan_play->ip, str2ip(SERVER_IP));
    CPY_IPV4(lan_play->subnet_mask, str2ip(SUBNET_MASK));
    lan_play->mac[0] = 0x6c;
    lan_play->mac[1] = 0x71;
    lan_play->mac[2] = 0xd9;
    lan_play->mac[3] = 0x1d;
    lan_play->mac[4] = 0x71;
    lan_play->mac[5] = 0x6f;
    arp_list_init(lan_play->arp_list);
    lan_play->arp_ttl = 30;
}

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char *devStr;
    pcap_t *dev;

    devStr = pcap_lookupdev(errBuf);
    if (devStr) {
        printf("Success: device %s\n", devStr);
    } else {
        fprintf(stderr, "Error: %s\n", errBuf);
        exit(1);
    }

    dev = pcap_open_live(devStr, 65535, 1, 0, errBuf);

    if (!dev) {
        fprintf(stderr, "Error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    set_filter(dev);

#if __APPLE__
	int fd;
    fd = pcap_fileno(dev); // fix mac os realtime
    if (set_immediate_mode(fd) == -1) {
        fprintf(stderr, "Error: BIOCIMMEDIATE failed %s\n", strerror(errno));
        exit(1);
    }
#endif

    struct lan_play lan_play;
    init_lan_play(&lan_play, dev);

    pcap_loop(dev, -1, (void(*)(u_char *, const struct pcap_pkthdr *, const u_char *))get_packet, (u_char*)&lan_play);

    pcap_close(dev);
    return 0;
}
