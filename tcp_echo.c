
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
/*
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
*/
#include <arpa/inet.h>

#define BUFLEN 2048

void error(const char *message) {
    perror(message);
    exit(1);
}

int main(int argc, char **argv) {
    int res;
    int port;
    if (argc < 2) port = 1099;
    else          port = atoi(argv[1]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error("socket");

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_addr = {0},
        .sin_port = htons(port),
    };

    res = bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (res < 0) error("bind");

    res = listen(sock, 1);
    if (res < 0) error("listen");

    struct sockaddr_in recv_addr = {0};
    socklen_t recv_len = sizeof(recv_addr);

    int lsock = accept(sock, (struct sockaddr *)&recv_addr, &recv_len);
    if (lsock < 0) error("accept");
    if (recv_len != sizeof(recv_addr)) error("recv len");

    while (true) {
        char buf[BUFLEN];

        int len = recv(lsock, buf, BUFLEN, 0);
        if (len < 0) error("recv");

        res = send(lsock, buf, len, 0);
        if (res < 0) error("send");
    }
}

