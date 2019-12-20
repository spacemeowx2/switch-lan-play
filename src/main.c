#include "lan-play.h"

// command-line options
struct cli_options options;

OPTIONS_DEF(socks5_server_addr);
OPTIONS_DEF(relay_server_addr);
uv_signal_t signal_int;

int list_interfaces(pcap_if_t *alldevs)
{
    int i = 0;
    pcap_if_t *d;
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        } else {
            printf(" (No description available)");
        }
        if (d->addresses) {
            struct pcap_addr *taddr;
            struct sockaddr_in *sin;
            char  revIP[100];
            bool  first = true;
            for (taddr = d->addresses; taddr; taddr = taddr->next)
            {
                sin = (struct sockaddr_in *)taddr->addr;
                if (sin->sin_family == AF_INET) {
                    strncpy(revIP, inet_ntoa(sin->sin_addr), sizeof(revIP));
                    if (first) {
                        printf("\n\tIP: [");
                        first = false;
                    } else {
                        putchar(',');
                    }
                    printf("%s", revIP);
                }
            }
            if (!first) {
                putchar(']');
            }
        }
        putchar('\n');
    }
    return i;
}

int parse_arguments(int argc, char **argv)
{
    #define CHECK_PARAM() if (1 >= argc - i) { \
        eprintf("%s: requires an argument\n", arg); \
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
    options.list_if = false;

    options.netif_ipaddr = NULL;
    options.netif_netmask = NULL;

    options.relay_server_addr = NULL;
    options.relay_username = NULL;
    options.relay_password = NULL;
    options.relay_password_file = NULL;

    options.socks5_server_addr = NULL;
    options.socks5_username = NULL;
    options.socks5_password = NULL;
    options.socks5_password_file = NULL;
    options.rpc = NULL;
    options.rpc_token = NULL;
    options.rpc_protocol = NULL;

    int i;
    for (i = 1; i < argc; i++) {
        char *arg = argv[i];

        if (!strcmp(arg, "--help")) {
            options.help = 1;
        } else if (!strcmp(arg, "--version")) {
            options.version = 1;
        // } else if (!strcmp(arg, "--netif-ipaddr")) {
        //     CHECK_PARAM();
        //     options.netif_ipaddr = argv[i + 1];
        //     i++;
        // } else if (!strcmp(arg, "--netif-netmask")) {
        //     CHECK_PARAM();
        //     options.netif_netmask = argv[i + 1];
        //     i++;
        } else if (!strcmp(arg, "--relay-server-addr")) {
            CHECK_PARAM();
            options.relay_server_addr = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--username")) {
            CHECK_PARAM();
            options.relay_username = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--password")) {
            CHECK_PARAM();
            options.relay_password = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--password-file")) {
            CHECK_PARAM();
            options.relay_password_file = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--socks5-server-addr")) {
            CHECK_PARAM();
            options.socks5_server_addr = argv[i + 1];
            i++;
        // } else if (!strcmp(arg, "--socks5-username")) {
        //     CHECK_PARAM();
        //     options.socks5_username = argv[i + 1];
        //     i++;
        // } else if (!strcmp(arg, "--socks5-password")) {
        //     CHECK_PARAM();
        //     options.socks5_password = argv[i + 1];
        //     i++;
        // } else if (!strcmp(arg, "--socks5-password-file")) {
        //     CHECK_PARAM();
        //     options.socks5_password_file = argv[i + 1];
        //     i++;
        } else if (!strcmp(arg, "--list-if")) {
            options.list_if = true;
        } else if (!strcmp(arg, "--broadcast")) {
            options.broadcast = true;
            options.relay_server_addr = "255.255.255.255:11451";
        } else if (!strcmp(arg, "--pmtu")) {
            CHECK_PARAM();
            options.pmtu = atoi(argv[i + 1]);
            i++;
        } else if (!strcmp(arg, "--fake-internet")) {
            options.fake_internet = true;
        } else if (!strcmp(arg, "--set-ionbf")) {
            setvbuf(stdout, NULL, _IONBF, 0);
            setvbuf(stderr, NULL, _IONBF, 0);
        } else if (!strcmp(arg, "--rpc")) {
            CHECK_PARAM();
            options.rpc = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--rpc-token")) {
            CHECK_PARAM();
            options.rpc_token = argv[i + 1];
            i++;
        } else if (!strcmp(arg, "--rpc-protocol")) {
            CHECK_PARAM();
            options.rpc_protocol = argv[i + 1];
            i++;
        } else {
            LLOG(LLOG_WARNING, "unknown paramter: %s", arg);
        }
    }

    if (options.help || options.version || options.list_if || options.rpc) {
        return 0;
    }
    if (!options.relay_server_addr) {
        if (options.socks5_server_addr) {
            options.relay_server_addr = "127.0.0.1:11451";
        } else {
            eprintf("--relay-server-addr is required\n");
        }
        // return -1;
    }
    if (options.socks5_username) {
        if (!options.socks5_password && !options.socks5_password_file) {
            eprintf("username given but password not given\n");
            return -1;
        }

        if (options.socks5_password && options.socks5_password_file) {
            eprintf("--password and --password-file cannot both be given\n");
            return -1;
        }
    }
    if (options.relay_username) {
        if (!options.relay_password && !options.relay_password_file) {
            eprintf("username given but password not given\n");
            return -1;
        }

        if (options.relay_password && options.relay_password_file) {
            eprintf("--password and --password-file cannot both be given\n");
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
        "        [--username <username>]\n"
        "        [--password <password>]\n"
        "        [--password-file <password-file>]\n"
        "        [--list-if]\n"
        "        [--pmtu <pmtu>]\n"
        "        [--socks5-server-addr <addr>]\n"
        "        [--rpc <address>]\n"
        "        [--rpc-token <token>]\n"
        "        [--rpc-protocol <rpc protocl>]\n"
        // "        [--socks5-username <username>]\n"
        // "        [--socks5-password <password>]\n"
        // "        [--socks5-password-file <file>]\n"
        "Address format is a.b.c.d:port (IPv4).\n"
        "RPC protocol could be tcp, ws. Default to ws.\n",
        name
    );
}

void walk_cb(uv_handle_t* handle, void* arg)
{
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
    // LLOG(LLOG_DEBUG, "walk %d %p", handle->type, handle->data);
}

void lan_play_signal_cb(uv_signal_t *signal, int signum)
{
    struct lan_play *lan_play = signal->data;
    eprintf("stopping signum: %d\n", signum);

    int ret = lan_play_close(lan_play);
    if (ret) {
        LLOG(LLOG_ERROR, "lan_play_close %d", ret);
    }

    ret = uv_signal_stop(&signal_int);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_signal_stop(signal_int) %d", ret);
    }

    uv_close((uv_handle_t *)&signal_int, NULL);

    uv_walk(lan_play->loop, walk_cb, lan_play);
}

void print_version()
{
    printf("switch-lan-play " LANPLAY_VERSION "\n");
}

void list_netif()
{
    pcap_if_t *alldevs;
    char err_buf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, err_buf)) {
        fprintf(stderr, "Error pcap_findalldevs: %s\n", err_buf);
        exit(1);
    }

    list_interfaces(alldevs);

    pcap_freealldevs(alldevs);
}

int old_main()
{
    char relay_server_addr[128] = { 0 };
    struct lan_play *lan_play = &real_lan_play;
    int ret;

    lan_play->loop = uv_default_loop();

    if (options.version) {
        print_version();
        return 0;
    }

    if (options.list_if) {
        list_netif();
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

    RT_ASSERT(uv_signal_init(lan_play->loop, &signal_int) == 0);
    RT_ASSERT(uv_signal_start(&signal_int, lan_play_signal_cb, SIGINT) == 0);
    signal_int.data = lan_play;

    printf("Opening interfaces\n");
    RT_ASSERT(lan_play_init(lan_play) == 0);

    ret = uv_run(lan_play->loop, UV_RUN_DEFAULT);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_run %d", ret);
    }

    LLOG(LLOG_DEBUG, "lan_play exit %d", ret);

    return ret;
}

int main(int argc, char **argv)
{
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
    if (options.rpc) {
        return rpc_main(options.rpc, options.rpc_token, options.rpc_protocol);
    } else {
        return old_main();
    }
}
