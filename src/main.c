#include "lan-play.h"

uint8_t SEND_BUFFER[BUFFER_SIZE];

void setFilter(pcap_t *dev)
{
    static struct bpf_program bpf;
    pcap_compile(dev, &bpf, "src host " CLIENT_IP, 1, 0);
    pcap_setfilter(dev, &bpf);
}

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char *devStr;

    devStr = pcap_lookupdev(errBuf);
    if (devStr) {
        printf("Success: device %s\n", devStr);
    } else {
        printf("Error: %s\n", errBuf);
        exit(1);
    }

    pcap_t *dev = pcap_open_live(devStr, 65535, 1, 0, errBuf);

    if (!dev) {
        printf("Error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    setFilter(dev);

    struct LanPlay lan_play;
    lan_play.dev = dev;
    lan_play.id = 0;
    lan_play.buffer = SEND_BUFFER;
    lan_play.identification = 0;
    lan_play.mac[0] = 0x6c;
    lan_play.mac[1] = 0x71;
    lan_play.mac[2] = 0xd9;
    lan_play.mac[3] = 0x1d;
    lan_play.mac[4] = 0x71;
    lan_play.mac[5] = 0x6f;

    pcap_loop(dev, -1, (void(*)(u_char *, const struct pcap_pkthdr *, const u_char *))getPacket, (u_char*)&lan_play);

    pcap_close(dev);
    return 0;
}
