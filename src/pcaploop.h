#ifndef _PCAPLOOP_H_
#define _PCAPLOOP_H_

#include <uv.h>
#include <pcap.h>

#ifndef PCAPLOOP_USE_POLL
#if defined(_WIN32)
#define PCAPLOOP_USE_POLL 0
#else
#define PCAPLOOP_USE_POLL 1
#endif
#endif

typedef struct uv_pcap_s uv_pcap_t;
typedef void (*uv_pcap_cb)(uv_pcap_t *handle, const struct pcap_pkthdr *pkt_header, const u_char *packet);
typedef void (*uv_pcap_close_cb)(uv_pcap_t *handle);

struct uv_pcap_s {
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
    uv_pcap_cb callback;

    void *data;
};

int uv_pcap_init(uv_loop_t *loop, uv_pcap_t *handle, uv_pcap_cb cb, pcap_t *dev);
void uv_pcap_close(uv_pcap_t *handle, uv_close_cb cb);

#endif
