#include "lan-play.h"

// command-line options
struct {
    int help;
    int version;

    char *netif;
    char *netif_ipaddr;
    char *netif_netmask;

    char *socks_server_addr;
    char *relay_server_addr;
    char *username;
    char *password;
    char *password_file;
} options;

uint8_t SEND_BUFFER[BUFFER_SIZE];

void set_filter(pcap_t *dev)
{
    char filter[100];
    static struct bpf_program bpf;
    snprintf(filter, sizeof(filter), "net %s %s", SUBNET_NET, SUBNET_MASK);
    pcap_compile(dev, &bpf, filter, 1, 0);
    pcap_setfilter(dev, &bpf);
}

void get_mac(struct lan_play *lan_play, pcap_if_t *d, pcap_t *p)
{
    if (get_mac_address(d, p, lan_play->mac) != 0) {
        fprintf(stderr, "Error when getting the MAC address\n");
        exit(1);
    }
    printf("Get MAC: ");
    PRINT_MAC(lan_play->mac);
    putchar('\n');
}

void init_pcap(struct lan_play *lan_play)
{
    pcap_t *dev;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *dev_name;
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
    }

    printf("Opening %s\n", d->name);
    dev = pcap_open_live(d->name, 65535, 1, 0, err_buf);

    if (!dev) {
        fprintf(stderr, "Error: pcap_open_live(): %s\n", err_buf);
        pcap_freealldevs(alldevs);
        exit(1);
    }
    set_filter(dev);
    get_mac(lan_play, d, dev);
    if (set_immediate_mode(dev) == -1) {
        fprintf(stderr, "Error: set_immediate_mode failed %s\n", strerror(errno));
        exit(1);
    }

    pcap_freealldevs(alldevs);

    lan_play->dev = dev;
}

void init_lan_play(struct lan_play *lan_play)
{
    lan_play->mac[0] = 0x00;
    lan_play->mac[1] = 0x00;
    lan_play->mac[2] = 0x00;
    lan_play->mac[3] = 0x00;
    lan_play->mac[4] = 0x00;
    lan_play->mac[5] = 0x00;
    lan_play->dev = NULL;
    lan_play->stop = false;

    init_pcap(lan_play);

    lan_play->id = 0;
    lan_play->buffer = SEND_BUFFER;
    lan_play->identification = 0;
    CPY_IPV4(lan_play->ip, str2ip(SERVER_IP));
    CPY_IPV4(lan_play->subnet_net, str2ip(SUBNET_NET));
    CPY_IPV4(lan_play->subnet_mask, str2ip(SUBNET_MASK));
    arp_list_init(lan_play->arp_list);
    lan_play->arp_ttl = 30;
}

void loop_lan_play(struct lan_play *lan_play)
{
    puts("Loop start");
    pcap_loop(lan_play->dev, -1, (void(*)(u_char *, const struct pcap_pkthdr *, const u_char *))get_packet, (u_char*)lan_play);
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
        }
    }

    if (options.help || options.version) {
        return 0;
    }
    if (!options.relay_server_addr) {
        fprintf(stderr, "--relay-server-addr is required\n");
        return -1;
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
        "        [--netif <netif>]"
        // "        [--netif-ipaddr <ipaddr>] default: 10.13.37.1\n"
        // "        [--netif-netmask <ipnetmask>] default: 255.255.0.0\n"
        "        --relay-server-addr <addr>\n"
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
    printf("switch-lan-play v0.0.0\n");
}

int main(int argc, char **argv)
{
    struct lan_play lan_play;
    pthread_t tid;

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

    if (parse_addr(options.relay_server_addr, &lan_play.server_addr) != 0) {
        LLOG(LLOG_ERROR, "Failed to parse --relay-server-addr %s", options.relay_server_addr);
    }

    proxy_init();

    forwarder_init(&lan_play);
    pthread_create(&tid, NULL, forwarder_thread, &lan_play);

    init_lan_play(&lan_play);

    loop_lan_play(&lan_play);

    pcap_close(lan_play.dev);

    pthread_join(tid, NULL);

    return 0;
}
