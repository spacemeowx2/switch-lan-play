#ifndef _UVL_LWIP_H_
#define _UVL_LWIP_H_

#define UVL_NBUF_LEN 10

#include <uv.h>

typedef struct uvl uvl_t;
typedef struct uvl_tcp uvl_tcp_t;
typedef struct uvl_write uvl_write_t;
typedef struct uvl_shutdown uvl_shutdown_t;

typedef int (*uvl_output_fn)(uvl_t *handle, const uv_buf_t bufs[], unsigned int nbufs);
typedef void (*uvl_close_cb)(uvl_t *handle);
typedef void (*uvl_connection_cb)(uvl_t *handle, int status);

typedef void (*uvl_alloc_tcp_cb)(uvl_tcp_t *client, size_t suggested_size, uv_buf_t* buf);
typedef void (*uvl_read_cb)(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf);
typedef void (*uvl_write_cb)(uvl_write_t *req, int status);
typedef void (*uvl_alloc_cb)(uvl_tcp_t *handle, size_t suggested_size, uv_buf_t* buf);
typedef void (*uvl_shutdown_cb)(uvl_shutdown_t *req, int status);
typedef void (*uvl_tcp_close_cb)(uvl_tcp_t *handle);

struct uvl_tcp_buf;
struct uvl_connection_req;
struct uvl {
    void *data;

    uvl_output_fn output;
    uvl_connection_cb connection_cb;
    uvl_close_cb close_cb;
    struct netif *the_netif;
    struct tcp_pcb *listener;
    struct tcp_pcb *waiting_pcb;
    uv_timer_t timer;
    int tcp_timer_mod4;

    int closed;
};
struct uvl_tcp {
    void *data;

    struct uvl_tcp_buf *buf;
    uvl_write_t *cur_write;
    uvl_write_t *tail_write;

    uv_async_t read_req;
    uv_async_t write_req;

    int closed;
    uvl_alloc_tcp_cb alloc_cb;
    uvl_read_cb read_cb;
    uvl_tcp_close_cb close_cb;
    struct tcp_pcb *pcb;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;

    uint32_t sent_bytes;
    uint32_t recv_bytes;

    int closed_handle;
};
struct uvl_write {
    void *data;

    uvl_tcp_t *client;
    const uv_buf_t *send_bufs;
    unsigned int send_nbufs;
    uint32_t sent_bufs;
    uint32_t sent;
    uint32_t pending;
    uint32_t total_sent;
    uint32_t total_len;
    uvl_write_cb write_cb;

    uvl_write_t *next;
};
struct uvl_shutdown {
    void *data;

    uvl_tcp_t *handle;
};

int uvl_init(uv_loop_t *loop, uvl_t *handle);
int uvl_bind(uvl_t *handle, uvl_output_fn output);
int uvl_input(uvl_t *handle, const uv_buf_t buf);
int uvl_listen(uvl_t *handle, uvl_connection_cb connection_cb);
int uvl_accept(uvl_t *handle, uvl_tcp_t *client);
int uvl_close(uvl_t *handle, uvl_close_cb close_cb);
int uvl_read_start(uvl_tcp_t *client, uvl_alloc_cb alloc_cb, uvl_read_cb read_cb);
int uvl_read_stop(uvl_tcp_t *client);
int uvl_write(uvl_write_t *req, uvl_tcp_t *client, const uv_buf_t bufs[], unsigned int nbufs, uvl_write_cb cb);
int uvl_shutdown(uvl_shutdown_t *req, uvl_tcp_t *client, uvl_shutdown_cb cb);
int uvl_tcp_init(uv_loop_t *loop, uvl_tcp_t *client);
int uvl_tcp_close(uvl_tcp_t *client, uvl_tcp_close_cb close_cb);

#endif // _UVL_LWIP_H_
