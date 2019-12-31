
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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

void *udp_echo(void *data) {
    int res;
    int *port_x = data;
    int port = *port_x;

    int sock = i_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) error("i_socket");

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_addr = {0},
        .sin_port = htons(port),
    };

    res = i_bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (res < 0) error("i_bind");

    while (true) {
        struct sockaddr_in recv_addr = {0};
        socklen_t recv_len = sizeof(recv_addr);
        char buf[BUFLEN];

        int len = i_recvfrom(sock, buf, BUFLEN, 0,
                (struct sockaddr *)&recv_addr, &recv_len);
        if (len < 0) error("i_recvfrom");
        if (recv_len != sizeof(recv_addr)) {
            // is this normal?
            fprintf(stderr, "bad recv_len\n");
        }

        res = i_sendto(sock, buf, len, 0,
                (struct sockaddr *)&recv_addr, recv_len);
        if (res < 0) error("i_sendto");
    }
}

