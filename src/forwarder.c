#include "lan-play.h"

void forwarder_init(struct lan_play *lan_play)
{
    int ret;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server_net;
    struct sockaddr_in server_addr;

    server_net = gethostbyname(SERVER_ADDR);
    if (server_net == NULL) {
        fprintf(stderr, "Error gethostbyname %s\n", strerror(errno));
        exit(1);
    }
    printf("%p %x\n", server_net, *(uint32_t*)server_net->h_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = *((struct in_addr *)server_net->h_addr);
    server_addr.sin_port = htons(SERVER_PORT);

    ret = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret != 0) {
        fprintf(stderr, "Error connect %d\n", ret);
        exit(1);
    }
    puts("Forwarder connected");
    lan_play->f_fd = fd;

    if (pthread_mutex_init(&lan_play->mutex, NULL) != 0) {
        fprintf(stderr, "Error pthread_mutex_init %s\n", strerror(errno));
        exit(1);
    }
    MUTEX_LOCK(&lan_play->mutex);
}

void *forwarder_thread(void *p)
{
    struct lan_play *lan_play = (struct lan_play *)p;


    return NULL;
}
