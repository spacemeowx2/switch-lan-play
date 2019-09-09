#include "lan-play.h"
#include "sha1.h"

#define RETURN_ERR(lan_play, ...) snprintf(lan_play->last_err, sizeof(lan_play->last_err), __VA_ARGS__); return -1

struct lan_play real_lan_play;
uint8_t SEND_BUFFER[BUFFER_SIZE];
void lan_play_pcap_handler(uv_pcap_t *handle, const struct pcap_pkthdr *pkt_header, const u_char *packet, const uint8_t *mac);

int init_pcap(struct lan_play *lan_play)
{
    int ret = uv_pcap_init(lan_play->loop, &lan_play->pcap, lan_play_pcap_handler);
    if (ret != 0) {
        RETURN_ERR(lan_play, "failed at uv_pcap_init");
    };

    return 0;
}

int lan_play_send_packet(struct lan_play *lan_play, void *data, int size)
{
    int ret = uv_pcap_sendpacket(&lan_play->pcap, data, size);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "uv_pcap_sendpacket %d", ret);
    }
    return ret;
}

int lan_play_close(struct lan_play *lan_play)
{
    int ret;

    uv_pcap_close(&lan_play->pcap);
    ret = packet_close(&lan_play->packet_ctx);
    if (ret != 0) return ret;

    if (options.relay_server_addr) {
        ret = lan_client_close(lan_play);
        if (ret != 0) return ret;
    }

    ret = gateway_close(lan_play->gateway);
    if (ret != 0) return ret;

    return 0;
}

void lan_play_pcap_handler(uv_pcap_t *handle, const struct pcap_pkthdr *pkt_header, const u_char *packet, const uint8_t *mac)
{
    struct lan_play *lan_play = handle->data;
    packet_set_mac(&lan_play->packet_ctx, mac);
    get_packet(&lan_play->packet_ctx, pkt_header, packet);
}

int lan_play_init(struct lan_play *lan_play)
{
    int ret = 0;
    uint8_t ip[4];
    uint8_t subnet_net[4];
    uint8_t subnet_mask[4];

    lan_play->broadcast = options.broadcast;
    lan_play->pmtu = options.pmtu;

    if (options.relay_server_addr) {
        if (parse_addr(options.relay_server_addr, &lan_play->server_addr) != 0) {
            RETURN_ERR(lan_play, "Failed to parse and get ip address. --relay-server-addr: %s", options.relay_server_addr);
        }
    }
    lan_play->username = options.relay_username;
    if (options.relay_password) {
        SHA1_CTX hashctx;
        SHA1Init(&hashctx);
        SHA1Update(&hashctx, (const unsigned char *)options.relay_password, strlen(options.relay_password));
        SHA1Final(lan_play->key, &hashctx);
    }

    ret = init_pcap(lan_play);
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
        30
    );
    if (ret != 0) return ret;

    if (options.relay_server_addr) {
        ret = lan_client_init(lan_play);
        if (ret != 0) return ret;
    }

    struct sockaddr_in proxy_server;
    struct sockaddr *proxy_server_ptr = NULL;
    if (options.socks5_server_addr) {
        proxy_server_ptr = (struct sockaddr *)&proxy_server;
        if (parse_addr(options.socks5_server_addr, &proxy_server) != 0) {
            RETURN_ERR(lan_play, "Failed to parse and get ip address. --socks5-server-addr: %s", options.socks5_server_addr);
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
