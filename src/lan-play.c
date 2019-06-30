#include "lan-play.h"

#define RETURN_ERR(lan_play, ...) snprintf(lan_play->last_err, sizeof(lan_play->last_err), __VA_ARGS__); return -1

struct lan_play real_lan_play;
uint8_t SEND_BUFFER[BUFFER_SIZE];

void set_filter(pcap_t *dev)
{
    char filter[100];
    static struct bpf_program bpf;

    uint32_t mask = READ_NET32(str2ip(SUBNET_MASK), 0);
    int num;
    for (num = 0; mask != 0 && num < 32; num++) mask <<= 1;

    snprintf(filter, sizeof(filter), "net %s/%d", SUBNET_NET, num);
    LLOG(LLOG_DEBUG, "filter: %s", filter);
    pcap_compile(dev, &bpf, filter, 1, 0);
    pcap_setfilter(dev, &bpf);
}

void get_mac(void *mac, pcap_if_t *d, pcap_t *p)
{
    if (get_mac_address(d, p, mac) != 0) {
        eprintf("Error when getting the MAC address\n");
        exit(1);
    }
    eprintf("Get MAC: ");
    PRINT_MAC(mac);
    eprintf("\n");
}

int init_pcap(struct lan_play *lan_play, void *mac)
{
    pcap_t *dev;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char err_buf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, err_buf)) {
        RETURN_ERR(lan_play, "Error pcap_findalldevs: %s", err_buf);
    }
    if (options.netif == NULL) {
        RETURN_ERR(lan_play, "netif not set");
    }

    for (d = alldevs; d; d = d->next) {
        if (!strcmp(d->name, options.netif)) {
            break;
        }
    }
    if (d == NULL) {
        RETURN_ERR(lan_play, "failed to find --netif: %s", options.netif);
    }

    dev = pcap_open_live(d->name, 65535, 1, 500, err_buf);

    if (!dev) {
        pcap_freealldevs(alldevs);
        RETURN_ERR(lan_play, "Error: pcap_open_live(): %s", err_buf);
    }
    set_filter(dev);
    get_mac(mac, d, dev);
    if (set_immediate_mode(dev) == -1) {
        RETURN_ERR(lan_play, "Error: set_immediate_mode failed %s", strerror(errno));
    }

    pcap_freealldevs(alldevs);

    lan_play->dev = dev;

    return 0;
}

int lan_play_send_packet(struct lan_play *lan_play, void *data, int size)
{
    int ret = pcap_sendpacket(lan_play->dev, data, size);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "lan_play_packet_send %d", ret);
    }
    return ret;
}

int lan_play_close(struct lan_play *lan_play)
{
    int ret;

    uv_pcap_close(&lan_play->pcap, NULL);
    ret = packet_close(&lan_play->packet_ctx);
    if (ret != 0) return ret;
    ret = lan_client_close(lan_play);
    if (ret != 0) return ret;
    ret = gateway_close(lan_play->gateway);
    if (ret != 0) return ret;

    return 0;
}

void lan_play_pcap_handler(uv_pcap_t *handle, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{
    struct lan_play *lan_play = handle->data;
    get_packet(&lan_play->packet_ctx, pkt_header, packet);
}

int lan_play_init(struct lan_play *lan_play)
{
    int ret = 0;
    uint8_t ip[4];
    uint8_t subnet_net[4];
    uint8_t subnet_mask[4];
    uint8_t mac[6];

    lan_play->dev = NULL;
    lan_play->broadcast = options.broadcast;
    lan_play->pmtu = options.pmtu;

    ret = init_pcap(lan_play, mac);
    if (ret != 0) return ret;

    CPY_IPV4(ip, str2ip(SERVER_IP));
    CPY_IPV4(subnet_net, str2ip(SUBNET_NET));
    CPY_IPV4(subnet_mask, str2ip(SUBNET_MASK));
    LLOG(LLOG_DEBUG, "packet init buffer %p", SEND_BUFFER);
    ret = packet_init(
        &lan_play->packet_ctx,
        lan_play,
        SEND_BUFFER,
        sizeof(SEND_BUFFER),
        ip,
        subnet_net,
        subnet_mask,
        mac,
        30
    );
    if (ret != 0) return ret;
    ret = lan_client_init(lan_play);
    if (ret != 0) return ret;

    struct sockaddr_in proxy_server;
    struct sockaddr *proxy_server_ptr = NULL;
    if (options.socks5_server_addr) {
        proxy_server_ptr = (struct sockaddr *)&proxy_server;
        if (parse_addr(options.socks5_server_addr, &proxy_server) != 0) {
            LLOG(LLOG_ERROR, "Failed to parse and get ip address. --socks5-server-addr: %s", options.socks5_server_addr);
            return -1;
        }
    }
    ret = gateway_init(
        &lan_play->gateway,
        &lan_play->packet_ctx,
        options.fake_internet,
        proxy_server_ptr,
        options.socks5_username,
        options.socks5_password
    );
    if (ret != 0) return ret;


    ret = uv_pcap_init(lan_play->loop, &lan_play->pcap, lan_play_pcap_handler, lan_play->dev);
    if (ret != 0) return ret;
    lan_play->pcap.data = lan_play;

    return ret;
}

int lan_play_gateway_send_packet(struct packet_ctx *packet_ctx, const void *data, uint16_t len)
{
    struct payload part;
    uint8_t dst_mac[6];
    const uint8_t *dst = (uint8_t *)data + IPV4_OFF_DST;

    if (!arp_get_mac_by_ip(packet_ctx, dst_mac, dst)) {
        return false;
    }

    part.ptr = data;
    part.len = len;
    part.next = NULL;

    return send_ether(
        packet_ctx,
        dst_mac,
        ETHER_TYPE_IPV4,
        &part
    );
}
