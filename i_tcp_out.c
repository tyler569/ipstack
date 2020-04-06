
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "socket.h"

#define BUFLEN 2048

static void error(const char *message) {
    perror(message);
    pthread_exit((void *)-1);
}

void *tcp_out(void *arg) {
    int res;
    int *pport = arg;
    int port = *pport;

    srand(time(0));
    uint16_t my_port = rand();

    int sock = i_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error("i_socket");

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        //.sin_addr = {0x00000000},
        .sin_addr = {0x02011fac},
        .sin_port = htons(my_port),
    };

    res = i_bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (res < 0) error("i_bind");

    struct sockaddr_in connect_addr = {
        .sin_family = AF_INET,
        .sin_addr = {0x01011fac}, // 172.31.1.1
        .sin_port = htons(port),
    };

    res = i_connect(sock, (struct sockaddr *)&connect_addr, sizeof(connect_addr));
    if (res < 0) error("i_connect");

    const char *message = "Hello World\n";
    res = i_send(sock, message, strlen(message), 0);
    if (res < 0) error("i_send");

    while (true) {
        char buf[BUFLEN];

        int len = i_recv(sock, buf, BUFLEN, 0);
        if (len < 0) error("i_recv");

        res = i_send(sock, buf, len, 0);
        if (res < 0) error("i_send");
    }
}

