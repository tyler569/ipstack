
#ifndef IPSTACK_SOCKET_H
#define IPSTACK_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"

int i_socket(int domain, int type, int protocol);
int i_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int i_listen(int sockfd, int backlog);
int i_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int i_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t i_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t i_sendto(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t i_recv(int sockfd, void *bud, size_t len, int flags);
ssize_t i_recvfrom(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen);

void socket_dispatch_udp(struct eth_hdr *);
void socket_dispatch_tcp(struct eth_hdr *);

#endif // IPSTACK_SOCKET_H

