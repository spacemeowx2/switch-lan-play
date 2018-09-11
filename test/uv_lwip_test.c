#include <uv.h>
#include <uv_lwip.h>
#include <assert.h>
#include <stdlib.h>
#include <pcap.h>

char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Organization: Nintendo\r\n\r\nok";
uv_loop_t loop;
uvl_t uvl;

void write_cb()
{

}

void read_cb(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf)
{
    uvl_write_t *req = malloc(sizeof(uvl_write_t));
    uv_buf_t b;

    b.base = resp;
    b.len = strlen(resp);

    printf(buf->base);

    uvl_write(req, handle, &b, 1, write_cb);
}

void alloc_cb(uvl_tcp_t *handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

void on_connect(uvl_t *handle, int status)
{
    assert(status == 0);

    uvl_tcp_t *client = malloc(sizeof(uvl_tcp_t));

    assert(uvl_tcp_init(handle->loop, client) == 0);
    assert(uvl_accept(handle, client) == 0);

    uvl_read_start(client, alloc_cb, read_cb);
}

void on_pcap(u_char *unused, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    printf("%d\n", hdr->len);
}

void thread_pcap(void *data)
{
    struct bpf_program bpf;
    char ebuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_t *pd;

    dev = pcap_lookupdev(ebuf);
    if (dev == NULL) {
        puts(ebuf);
        return;
    }
    printf("capture on %s\n", dev);
    pd = pcap_open_live(dev, 1024, 0, 1000, ebuf);
    assert(pd);

    assert(pcap_compile(pd, &bpf, "net 10.13.0.0/16", 1, 0) == 0);
    assert(pcap_setfilter(pd, &bpf) == 0);

    pcap_loop(pd, 5, on_pcap, NULL);

    pcap_close(pd);
}

int main()
{
    assert(uv_loop_init(&loop) == 0);

    assert(uvl_init(&loop, &uvl) == 0);

    assert(uvl_listen(&uvl, on_connect) == 0);

    uv_thread_t tid;
    assert(uv_thread_create(&tid, thread_pcap, &uvl) == 0);

    return uv_run(&loop, UV_RUN_DEFAULT);
}
