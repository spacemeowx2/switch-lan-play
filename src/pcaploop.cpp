#include "config.h"
#include "pcaploop.h"
#include "helper.h"
#include <base/llog.h>
#include <unordered_map>

#ifndef PCAPLOOP_USE_POLL
#if defined(_WIN32)
#define PCAPLOOP_USE_POLL 0
#else
#define PCAPLOOP_USE_POLL 1
#endif
#endif

typedef struct uv_pcap_interf_s uv_pcap_interf_t;
typedef void (*uv_pcap_interf_cb)(uv_pcap_interf_t *handle, const struct pcap_pkthdr *pkt_header, const u_char *packet);
typedef void (*uv_pcap_interf_close_cb)(uv_pcap_interf_t *handle);
static int uv_pcap_interf_init(uv_loop_t *loop, uv_pcap_interf_t *handle, uv_pcap_interf_cb cb, pcap_t *dev, uint8_t *mac);
static void uv_pcap_interf_close(uv_pcap_interf_t *handle, uv_close_cb cb);
static int uv_pcap_interf_sendpacket(uv_pcap_interf_t *handle, const u_char *data, int size);
static u_char EmptyMac[6] = {0,0,0,0,0,0};

struct uv_pcap_interf_s {
#if PCAPLOOP_USE_POLL
    int fd;
    uv_poll_t poll;
#else
    uv_async_t get_packet_async;
    uv_sem_t get_packet_sem;
    uv_thread_t libpcap_thread;
    const struct pcap_pkthdr *pkthdr;
    const u_char *packet;
#endif
    pcap_t *dev;
    uv_pcap_interf_cb callback;
    uint8_t mac[6];

    void *data;
};
struct uv_pcap_inner {
    std::unordered_map<uint64_t, uv_pcap_interf_t *> map;
    uv_pcap_interf_t *interfaces;
    int count;
};

static uint64_t mac2int(const uint8_t *mac)
{
    uint64_t r = 0;
    memcpy(&r, mac, 6);
    return r;
}

static void int2mac(const uint64_t i, uint8_t *mac)
{
    memcpy(mac, &i, 6);
}

static void set_filter(pcap_t *dev, const uint8_t *mac)
{
    char filter[100];
    static struct bpf_program bpf;

    uint32_t mask = READ_NET32(str2ip(SUBNET_MASK), 0);
    int num;
    for (num = 0; mask != 0 && num < 32; num++) mask <<= 1;

    snprintf(filter, sizeof(filter), "net %s/%d and not ether src %02x:%02x:%02x:%02x:%02x:%02x", SUBNET_NET, num,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    // LLOG(LLOG_DEBUG, "filter: %s", filter);
    pcap_compile(dev, &bpf, filter, 1, 0);
    pcap_setfilter(dev, &bpf);
    pcap_freecode(&bpf);
}


static void uv_pcap_callback(uv_pcap_interf_t *h, const struct pcap_pkthdr *pkt_header, const u_char *packet) {
    uv_pcap_t *handle = (uv_pcap_t *)h->data;
    auto key = mac2int(packet + 0);
    handle->inner->map[key] = h;
    handle->cb(handle, pkt_header, packet, h->mac);
}
int uv_pcap_sendpacket(uv_pcap_t *handle, const u_char *data, int size)
{
    auto inner = handle->inner;
    auto key = mac2int(data + 6);
    auto map = inner->map;

    auto search = map.find(key);

    if (search != map.end()) {
        auto item = search->second;
        int ret = uv_pcap_interf_sendpacket(item, data, size);
        if (ret != 0) {
            LLOG(LLOG_DEBUG, "uv_pcap_interf_sendpacket failed %d", ret);
        }
    } else {
        for (int i = 0; i < inner->count; i++) {
            int ret = uv_pcap_interf_sendpacket(&inner->interfaces[i], data, size);
            if (ret != 0) {
                LLOG(LLOG_DEBUG, "uv_pcap_interf_sendpacket failed %d", ret);
            }
        }
        // LLOG(LLOG_DEBUG, "cache not hit %llu", key);
    }

    return 0;
}

int uv_pcap_init(uv_loop_t *loop, uv_pcap_t *handle, uv_pcap_cb cb, char *netif)
{
    handle->cb = cb;
    handle->inner = new uv_pcap_inner;
    auto inner = handle->inner;
    pcap_if_t *alldevs;
    char err_buf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, err_buf)) {
        fprintf(stderr, "Error pcap_findalldevs: %s\n", err_buf);
        exit(1);
    }
    int i = 0;
    pcap_if_t *d;

    for (d = alldevs; d; d = d->next) {
        i++;
        if (netif != NULL) {
            int netif_index = atoi(netif);
            if (i == netif_index) {
                netif = strdup(d->name);
            }
        }
    }
    if (i == 0) {
        fprintf(stderr, "Error pcap_findalldevs 0 item\n");
        exit(1);
    }
    inner->interfaces = new uv_pcap_interf_t[i];
    i = 0;
    for (d = alldevs; d; d = d->next) {
        pcap_t *dev;
        int ret;
        if (netif != NULL) {
            if (!strcmp(d->name, netif)) {
                printf("found interface: %s\n", d->name);
                // found requested interface
                dev = pcap_open_live(d->name, 65535, 1, 500, err_buf);
                if (!dev) {
                    LLOG(LLOG_DEBUG, "open %s fail", d->name);
                    goto fail_single;
                }

                auto datalink = pcap_datalink(dev);
                if (datalink != DLT_EN10MB) {
                    LLOG(LLOG_DEBUG, "open specified interface: %s fail: datalink(%d)", d->name, datalink);
                    goto fail_single;
                }

                uint8_t mac[6];
                if (get_mac_address(d, dev, mac) != 0) {
                    LLOG(LLOG_DEBUG, "open specified interface: %s fail: get mac", d->name);
                    goto fail_single;
                }
                if (memcmp(EmptyMac, mac, 6) == 0) {
                    LLOG(LLOG_DEBUG, "open specified interface: %s fail: get all zero mac", d->name);
                    goto fail_single;
                }

                set_filter(dev, mac);

                if (set_immediate_mode(dev) == -1) {
                    LLOG(LLOG_DEBUG, "open specified interface: %s fail: set_immediate_mode %s", d->name, strerror(errno));
                    goto fail_single;
                }

                ret = uv_pcap_interf_init(loop, &inner->interfaces[i], uv_pcap_callback, dev, mac);
                if (ret) {
                    LLOG(LLOG_DEBUG, "open specified interface: %s fail: pcap init", d->name);
                    goto fail_single;
                }
                inner->interfaces[i].data = handle;
                i++;
                LLOG(LLOG_DEBUG, "open specified interface: %s ok", d->name);
                break;
            }
            continue;
            fail_single:
                pcap_close(dev);
                break;
        }

        dev = pcap_open_live(d->name, 65535, 1, 500, err_buf);
        if (!dev) {
            LLOG(LLOG_DEBUG, "open %s fail", d->name);
            continue;
        }

        auto datalink = pcap_datalink(dev);
        if (datalink != DLT_EN10MB) {
            LLOG(LLOG_DEBUG, "open %s fail: datalink(%d)", d->name, datalink);
            goto fail_next;
        }

        uint8_t mac[6];
        if (get_mac_address(d, dev, mac) != 0) {
            LLOG(LLOG_DEBUG, "open %s fail: get mac", d->name);
            goto fail_next;
        }
        if (memcmp(EmptyMac, mac, 6) == 0) {
            LLOG(LLOG_DEBUG, "open %s fail: get all zero mac", d->name);
            goto fail_next;
        }

        set_filter(dev, mac);

        if (set_immediate_mode(dev) == -1) {
            LLOG(LLOG_DEBUG, "open %s fail: set_immediate_mode %s", d->name, strerror(errno));
            goto fail_next;
        }

        ret = uv_pcap_interf_init(loop, &inner->interfaces[i], uv_pcap_callback, dev, mac);
        if (ret) {
            LLOG(LLOG_DEBUG, "open %s fail: pcap init", d->name);
            goto fail_next;
        }
        inner->interfaces[i].data = handle;
        i++;
        LLOG(LLOG_DEBUG, "open %s ok", d->name);
        continue;
fail_next:
        pcap_close(dev);
    }
    inner->count = i;
    pcap_freealldevs(alldevs);
    printf("pcap loop start\n");
    return 0;
}
void uv_pcap_close(uv_pcap_t *handle)
{
    auto inner = handle->inner;
    inner->map.clear();
    for (int i = 0; i < inner->count; i++) {
        uv_pcap_interf_close(&inner->interfaces[i], NULL);
    }
    printf("pcap loop stop\n");
}

static int uv_pcap_interf_sendpacket(uv_pcap_interf_t *handle, const u_char *data, int size)
{
    u_char old[6];
    u_char *d = (u_char *)data;
    CPY_MAC(old, d + 6);
    CPY_MAC(d + 6, handle->mac);
    int ret = pcap_sendpacket(handle->dev, data, size);
    CPY_MAC(d + 6, old);

    return ret;
}


#if PCAPLOOP_USE_POLL

static void poll_handler(uv_poll_t *handle, int status, int events);

static int uv_pcap_interf_init(uv_loop_t *loop, uv_pcap_interf_t *handle, uv_pcap_interf_cb cb, pcap_t *dev, uint8_t *mac)
{
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(dev, 1, errbuf) == -1) {
        LLOG(LLOG_ERROR, "setnonblock %s", errbuf);
    }
    handle->poll.data = handle;
    handle->fd = pcap_get_selectable_fd(dev);
    handle->dev = dev;
    handle->callback = cb;
    CPY_MAC(handle->mac, mac);
    ret = uv_poll_init(loop, &handle->poll, handle->fd);
    if (ret) return ret;
    ret = uv_poll_start(&handle->poll, UV_READABLE, poll_handler);
    if (ret) return ret;
    return 0;
}

static void uv_pcap_interf_close(uv_pcap_interf_t *handle, uv_close_cb cb)
{
    int ret = uv_poll_stop(&handle->poll);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_poll_stop %d", ret);
    }
}

static void poll_callback(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{
    uv_pcap_interf_t *handle = (uv_pcap_interf_t *)data;

    handle->callback(handle, pkt_header, packet);
}

static void poll_handler(uv_poll_t *poll, int status, int events)
{
    uv_pcap_interf_t *handle = (uv_pcap_interf_t *)poll->data;
    int count;

    if (events & UV_READABLE) {
        do {
            count = pcap_dispatch(handle->dev, 1, poll_callback, (u_char *)handle);
        } while (count > 0);
    }
}

#else

static void get_packet_async_cb(uv_async_t *async);
static void libpcap_thread_func(void *data);
static void libpcap_handler(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet);

int uv_pcap_interf_init(uv_loop_t *loop, uv_pcap_interf_t *handle, uv_pcap_interf_cb cb, pcap_t *dev, uint8_t *mac)
{
    int ret;
    ret = uv_async_init(loop, &handle->get_packet_async, get_packet_async_cb);
    if (ret) return ret;
    ret = uv_sem_init(&handle->get_packet_sem, 0);
    if (ret) return ret;
    handle->get_packet_async.data = handle;
    handle->callback = cb;
    handle->dev = dev;
    CPY_MAC(handle->mac, mac);
    ret = uv_thread_create(&handle->libpcap_thread, libpcap_thread_func, handle);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_thread_create %d", ret);
        return ret;
    }
    return 0;
}

void uv_pcap_interf_close(uv_pcap_interf_t *handle, uv_close_cb cb)
{
    pcap_breakloop(handle->dev);
    int ret = uv_thread_join(&handle->libpcap_thread);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_thread_join %d", ret);
    }
    uv_close((uv_handle_t *)&handle->get_packet_async, cb);
}

static void get_packet_async_cb(uv_async_t *async)
{
    uv_pcap_interf_t *handle = (uv_pcap_interf_t *)async->data;

    handle->callback(handle, handle->pkthdr, handle->packet);

    uv_sem_post(&handle->get_packet_sem);
}

static void libpcap_thread_func(void *data)
{
    uv_pcap_interf_t *handle = (uv_pcap_interf_t *)data;
    int ret = 0;

    ret = pcap_loop(handle->dev, -1, libpcap_handler, (u_char *)data);
    if (ret < 0 && ret != PCAP_ERROR_BREAK) {
        LLOG(LLOG_ERROR, "pcap_loop %d", ret);
    }

    pcap_close(handle->dev);
}

static void libpcap_handler(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{
    uv_pcap_interf_t *handle = (uv_pcap_interf_t *)data;

    handle->pkthdr = pkt_header;
    handle->packet = packet;

    if (uv_async_send(&handle->get_packet_async)) {
        LLOG(LLOG_WARNING, "libpcap_handler uv_async_send");
    }

    uv_sem_wait(&handle->get_packet_sem);
}

#endif
