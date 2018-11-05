#include "lan-play.h"

// command-line options
struct {
    int help;
    int version;

    bool broadcast;
    int pmtu;
    bool fake_internet;

    char *netif;
    char *netif_ipaddr;
    char *netif_netmask;

    char *socks_server_addr;
    char *relay_server_addr;
    char *username;
    char *password;
    char *password_file;
} options;
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
        fprintf(stderr, "Error when getting the MAC address\n");
        exit(1);
    }
    printf("Get MAC: ");
    PRINT_MAC(mac);
    putchar('\n');
}

void init_pcap(struct lan_play *lan_play, void *mac)
{
    pcap_t *dev;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char err_buf[PCAP_ERRBUF_SIZE];
    int i;
    int arg_inum;

    if (pcap_findalldevs(&alldevs, err_buf)) {
        fprintf(stderr, "Error pcap_findalldevs: %s\n", err_buf);
        exit(1);
    }
    if (options.netif == NULL) {
        i = 0;
        for (d = alldevs; d; d = d->next) {
            printf("%d. %s", ++i, d->name);
            if (d->description) {
                printf(" (%s)", d->description);
            } else {
                printf(" (No description available)");
            }
            if (d->addresses) {
                printf("\n\tIP: [");
                struct pcap_addr *taddr;
                struct sockaddr_in *sin;
                char  revIP[100];
                for (taddr = d->addresses; taddr; taddr = taddr->next)
                {
                    sin = (struct sockaddr_in *)taddr->addr;
                    if (sin->sin_family == AF_INET) {
                        strncpy(revIP, inet_ntoa(sin->sin_addr), sizeof(revIP));
                        printf("%s", revIP);
                        if (taddr->next)
                            putchar(',');
                    }
                }
                putchar(']');
            }
            putchar('\n');
        }

        printf("Enter the interface number (1-%d):", i);
        scanf("%d", &arg_inum);
        for (d = alldevs, i = 0; i < arg_inum - 1; d = d->next, i++);
    } else {
        for (d = alldevs; d; d = d->next) {
            if (!strcmp(d->name, options.netif)) {
                break;
            }
        }
        if (d == NULL) {
            LLOG(LLOG_ERROR, "failed to find --netif: %s", options.netif);
            exit(1);
        }
    }

    printf("Opening %s\n", d->name);
    dev = pcap_open_live(d->name, 65535, 1, 500, err_buf);

    if (!dev) {
        fprintf(stderr, "Error: pcap_open_live(): %s\n", err_buf);
        pcap_freealldevs(alldevs);
        exit(1);
    }
    set_filter(dev);
    get_mac(mac, d, dev);
    if (set_immediate_mode(dev) == -1) {
        fprintf(stderr, "Error: set_immediate_mode failed %s\n", strerror(errno));
        exit(1);
    }

    pcap_freealldevs(alldevs);

    lan_play->dev = dev;
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

    ret = packet_close(&lan_play->packet_ctx);
    if (ret != 0) return ret;
    ret = lan_client_close(lan_play);
    if (ret != 0) return ret;
    ret = gateway_close(&lan_play->gateway);
    if (ret != 0) return ret;

    ret = uv_signal_stop(&lan_play->signal_int);
    if (ret != 0) return ret;

    uv_close((uv_handle_t *)&lan_play->signal_int, NULL);
    uv_close((uv_handle_t *)&lan_play->get_packet_async, NULL);

    return 0;
}

int lan_play_init(struct lan_play *lan_play)
{
    int ret = 0;
    uint8_t ip[4];
    uint8_t subnet_net[4];
    uint8_t subnet_mask[4];
    uint8_t mac[6];

    lan_play->dev = NULL;
    lan_play->stop = false;
    lan_play->broadcast = options.broadcast;
    lan_play->pmtu = options.pmtu;

    init_pcap(lan_play, mac);

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
        30,
        &lan_play->gateway
    );
    if (ret != 0) return ret;
    ret = lan_client_init(lan_play);
    if (ret != 0) return ret;
    ret = gateway_init(&lan_play->gateway, &lan_play->packet_ctx, options.fake_internet);
    if (ret != 0) return ret;

    return 0;
}

int parse_arguments(int argc, char **argv)
{
    #define CHECK_PARAM() if (1 >= argc - i) { \
        fprintf(stderr, "%s: requires an argument\n", arg); \
        return -1; \
    }
    if (argc <= 0) {
        return -1;
    }

    options.help = 0;
    options.version = 0;

    options.broadcast = false;
    options.pmtu = 0;
    options.fake_internet = false;

    options.netif = NULL;
    options.netif_ipaddr = NULL;
    options.netif_netmask = NULL;

    options.socks_server_addr = NULL;
    options.relay_server_addr = NULL;
    options.username = NULL;
    options.password = NULL;
    options.password_file = NULL;

    int i;
    for (i = 0; i < argc; i++) {
        char *arg = argv[i];

        if (!strcmp(arg, "--help")) {
            options.help = 1;
        } else if (!strcmp(arg, "--version")) {
            options.version = 1;
        } else if (!strcmp(arg, "--netif-ipaddr")) {
            CHECK_PARAM();
            options.netif_ipaddr = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--netif-netmask")) {
            CHECK_PARAM();
            options.netif_netmask = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--relay-server-addr")) {
            CHECK_PARAM();
            options.relay_server_addr = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--socks-server-addr")) {
            CHECK_PARAM();
            options.socks_server_addr = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--username")) {
            CHECK_PARAM();
            options.username = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--password")) {
            CHECK_PARAM();
            options.password = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--password-file")) {
            CHECK_PARAM();
            options.password_file = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--netif")) {
            CHECK_PARAM();
            options.netif = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--broadcast")) {
            options.broadcast = true;
            options.relay_server_addr = "255.255.255.255:11451";
            i++;
        } else if (!strcmp(arg, "--pmtu")) {
            CHECK_PARAM();
            options.pmtu = atoi(argv[i + 1]);
            i++;
        } else if (!strcmp(arg, "--fake-internet")) {
            options.fake_internet = true;
        }
    }

    if (options.help || options.version) {
        return 0;
    }
    if (!options.relay_server_addr) {
        fprintf(stderr, "--relay-server-addr is required\n");
        // return -1;
    }
    if (options.username) {
        if (!options.password && !options.password_file) {
            fprintf(stderr, "username given but password not given\n");
            return -1;
        }

        if (options.password && options.password_file) {
            fprintf(stderr, "--password and --password-file cannot both be given\n");
            return -1;
        }
    }

    return 0;
}

void print_help(const char *name)
{
    printf(
        "Usage:\n"
        "    %s\n"
        "        [--help]\n"
        "        [--version]\n"
        "        [--broadcast]\n"
        "        [--fake-internet]\n"
        // "        [--netif-ipaddr <ipaddr>] default: 10.13.37.1\n"
        // "        [--netif-netmask <ipnetmask>] default: 255.255.0.0\n"
        "        [--relay-server-addr <addr>]\n"
        "        [--netif <netif>]\n"
        // "        [--socks-server-addr <addr>]\n"
        // "        [--username <username>]\n"
        // "        [--password <password>]\n"
        // "        [--password-file <file>]\n"
        "Address format is a.b.c.d:port (IPv4).\n",
        name
    );
}

void print_version()
{
    printf("switch-lan-play " LANPLAY_VERSION "\n");
}

void lan_play_libpcap_thread(void *data)
{
    struct lan_play *lan_play = (struct lan_play *)data;
    pcap_t *p = lan_play->dev;
    struct pcap_pkthdr *pkt_header;
    const u_char *packet;
    int ret;

    puts("pcap loop start");
    while (1) {
        ret = pcap_next_ex(p, &pkt_header, &packet);
        if (lan_play->stop) {
            break;
        }
        if (ret == 0) continue;
        if (ret != 1) {
            LLOG(LLOG_ERROR, "pcap_next_ex %d", ret);
            assert(0);
        }

        lan_play->pkthdr = pkt_header;
        lan_play->packet = packet;

        if (uv_async_send(&lan_play->get_packet_async)) {
            LLOG(LLOG_WARNING, "lan_play_get_packet uv_async_send");
        }

        uv_sem_wait(&lan_play->get_packet_sem);
    }
    puts("pcap loop stop");

    pcap_close(lan_play->dev);
}

void lan_play_get_packet_async_cb(uv_async_t *async)
{
    struct lan_play *lan_play = (struct lan_play *)async->data;
    assert(lan_play == &real_lan_play);

    get_packet(&lan_play->packet_ctx, lan_play->pkthdr, lan_play->packet);

    uv_sem_post(&lan_play->get_packet_sem);
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

void walk_cb(uv_handle_t* handle, void* arg)
{
    LLOG(LLOG_DEBUG, "walk %d %p", handle->type, handle->data);
}

void lan_play_signal_cb(uv_signal_t *signal, int signum)
{
    struct lan_play *lan_play = signal->data;
    lan_play->stop = true;
    printf("stopping signum: %d\n", signum);

    int ret = lan_play_close(lan_play);
    if (ret) {
        LLOG(LLOG_ERROR, "lan_play_close %d", ret);
    }

    uv_walk(lan_play->loop, walk_cb, lan_play);
}

int main(int argc, char **argv)
{
    char relay_server_addr[128] = { 0 };
    struct lan_play *lan_play = &real_lan_play;
    int ret;

    lan_play->loop = &lan_play->real_loop;

    if (parse_arguments(argc, argv) != 0) {
        LLOG(LLOG_ERROR, "Failed to parse arguments");
        print_help(argv[0]);
        return 1;
    }

    if (options.help) {
        print_version();
        print_help(argv[0]);
        return 0;
    }
    if (options.version) {
        print_version();
        return 0;
    }

    if (options.relay_server_addr == NULL) {
        printf("Input the relay server address [ domain/ip:port ]:");
        scanf("%100s", relay_server_addr);
        options.relay_server_addr = relay_server_addr;
    }

    if (parse_addr(options.relay_server_addr, &lan_play->server_addr) != 0) {
        LLOG(LLOG_ERROR, "Failed to parse and get ip address. --relay-server-addr: %s", options.relay_server_addr);
        return -1;
    }

    RT_ASSERT(uv_loop_init(lan_play->loop) == 0);
    RT_ASSERT(uv_async_init(lan_play->loop, &lan_play->get_packet_async, lan_play_get_packet_async_cb) == 0);
    RT_ASSERT(uv_sem_init(&lan_play->get_packet_sem, 0) == 0);
    RT_ASSERT(uv_signal_init(lan_play->loop, &lan_play->signal_int) == 0);
    RT_ASSERT(uv_signal_start(&lan_play->signal_int, lan_play_signal_cb, SIGINT) == 0);
    lan_play->get_packet_async.data = lan_play;
    lan_play->signal_int.data = lan_play;

    RT_ASSERT(lan_play_init(lan_play) == 0);

    ret = uv_thread_create(&lan_play->libpcap_thread, lan_play_libpcap_thread, lan_play);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_thread_create %d", ret);
    }

    ret = uv_run(lan_play->loop, UV_RUN_DEFAULT);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_run %d", ret);
    }

    ret = uv_thread_join(&lan_play->libpcap_thread);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_thread_join %d", ret);
    }

    LLOG(LLOG_DEBUG, "lan_play exit %d", ret);

    return ret;
}
