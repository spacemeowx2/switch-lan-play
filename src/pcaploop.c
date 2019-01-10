#include "pcaploop.h"
#include <base/llog.h>

#if PCAPLOOP_USE_POLL

static void poll_handler(uv_poll_t *handle, int status, int events);

int uv_pcap_init(uv_loop_t *loop, uv_pcap_t *handle, uv_pcap_cb cb, pcap_t *dev)
{
    int ret;
    handle->poll.data = handle;
    handle->fd = pcap_get_selectable_fd(dev);
    handle->dev = dev;
    handle->callback = cb;
    ret = uv_poll_init(loop, &handle->poll, handle->fd);
    if (ret) return ret;
    ret = uv_poll_start(&handle->poll, UV_READABLE, poll_handler);
    if (ret) return ret;
    puts("pcap loop start");
    return 0;
}

void uv_pcap_close(uv_pcap_t *handle, uv_close_cb cb)
{
    int ret = uv_poll_stop(&handle->poll);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_poll_stop %d", ret);
    }
    puts("pcap loop stop");
}

static void poll_callback(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{
    uv_pcap_t *handle = (uv_pcap_t *)data;

    handle->callback(handle, pkt_header, packet);
}

static void poll_handler(uv_poll_t *poll, int status, int events)
{
    uv_pcap_t *handle = poll->data;
    int count;

    if (events & UV_READABLE) {
        do {
            count = pcap_dispatch(handle->dev, 1, poll_callback, (u_char *)handle);
        } while (count > 0);
    }
}

#else

static void get_packet_async_cb(uv_async_t *async);
static void libpcap_thread(void *data);
static void libpcap_handler(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet);

int uv_pcap_init(uv_loop_t *loop, uv_pcap_t *handle, uv_pcap_cb cb, pcap_t *dev)
{
    int ret;
    ret = uv_async_init(loop, &handle->get_packet_async, get_packet_async_cb);
    if (ret) return ret;
    ret = uv_sem_init(&handle->get_packet_sem, 0);
    if (ret) return ret;
    handle->get_packet_async.data = handle;
    handle->callback = cb;
    handle->dev = dev;
    ret = uv_thread_create(&handle->libpcap_thread, libpcap_thread, handle);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_thread_create %d", ret);
        return ret;
    }
    return 0;
}

void uv_pcap_close(uv_pcap_t *handle, uv_close_cb cb)
{
    pcap_breakloop(handle->dev);
    int ret = uv_thread_join(&handle->libpcap_thread);
    if (ret) {
        LLOG(LLOG_ERROR, "uv_thread_join %d", ret);
    }
    uv_close((uv_handle_t *)&handle->get_packet_async, NULL);
}

static void get_packet_async_cb(uv_async_t *async)
{
    uv_pcap_t *handle = (uv_pcap_t *)async->data;

    handle->callback(handle, handle->pkthdr, handle->packet);

    uv_sem_post(&handle->get_packet_sem);
}

static void libpcap_thread(void *data)
{
    uv_pcap_t *handle = (uv_pcap_t *)data;
    int ret = 0;

    puts("pcap loop start");

    ret = pcap_loop(handle->dev, -1, libpcap_handler, data);
    if (ret < 0) {
        LLOG(LLOG_ERROR, "pcap_loop %d", ret);
    }

    puts("pcap loop stop");

    pcap_close(handle->dev);
}

static void libpcap_handler(u_char *data, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{
    uv_pcap_t *handle = (uv_pcap_t *)data;

    handle->pkthdr = pkt_header;
    handle->packet = packet;

    if (uv_async_send(&handle->get_packet_async)) {
        LLOG(LLOG_WARNING, "libpcap_handler uv_async_send");
    }

    uv_sem_wait(&handle->get_packet_sem);
}

#endif
