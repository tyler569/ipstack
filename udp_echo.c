
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
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

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) error("socket");

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_addr = {0},
        .sin_port = htons(port),
    };

    res = bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (res < 0) error("bind");

    while (true) {
        struct sockaddr_in recv_addr = {0};
        socklen_t recv_len = sizeof(recv_addr);
        char buf[BUFLEN];

        int len = recvfrom(sock, buf, BUFLEN, 0,
                (struct sockaddr *)&recv_addr, &recv_len);
        if (len < 0) error("recvfrom");
        if (recv_len != sizeof(recv_addr)) {
            // is this normal?
            fprintf(stderr, "bad recv_len\n");
        }

        res = sendto(sock, buf, len, 0,
                (struct sockaddr *)&recv_addr, recv_len);
        if (res < 0) error("sendto");
    }
}

