#include <uv.h>
#include <uv_lwip.h>
#include <assert.h>
#include <stdlib.h>

uv_loop_t loop;
uvl_t uvl;

void read_cb(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf)
{

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

int main()
{
    assert(uv_loop_init(&loop) == 0);

    assert(uvl_init(&loop, &uvl) == 0);

    assert(uvl_listen(&uvl, on_connect) == 0);

    return uv_run(&loop, UV_RUN_DEFAULT);
}
