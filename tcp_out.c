
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error("socket");

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_addr = {0},
        .sin_port = 0,
    };

    res = bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (res < 0) error("bind");

    struct sockaddr_in connect_addr = {
        .sin_family = AF_INET,
        .sin_addr = {0x0100007f}, // 127.0.0.1
        .sin_port = htons(port),
    };

    res = connect(sock, (struct sockaddr *)&connect_addr, sizeof(connect_addr));
    if (res < 0) error("connect");

    const char *message = "Hello World\n";
    send(sock, message, strlen(message), 0);

    while (true) {
        char buf[BUFLEN];

        int len = recv(sock, buf, BUFLEN, 0);
        if (len < 0) error("recv");

        res = send(sock, buf, len, 0);
        if (res < 0) error("send");
    }
}

