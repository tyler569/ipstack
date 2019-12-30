
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "net.h"

enum socket_state {
    IDLE = 0,
    REQUESTED,
    BOUND,
    LISTENING,
    OUTBOUND,
};

struct accept_data {
    // IPism
    uint32_t remote_ip;
    uint16_t remote_port;
};

struct socket_impl {
    bool valid;
    enum socket_state state;

    int domain;
    int type;
    int protocol;

    int ip_id;

    // IPism
    // NETWORK byte order
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;

    pthread_mutex_t listen_mtx;
    pthread_cond_t listen_cond;
    struct accept_data accept_data;

    pthread_mutex_t data_mtx;
    pthread_cond_t data_cond;
    void *pending_data;
    int pending_data_len;
    uint32_t pending_remote_ip;
    uint16_t pending_remote_port;
};

#define N_MAXSOCKETS 256

struct socket_impl sockets[N_MAXSOCKETS] = {0};

static int next_avail() {
    int i = -1;
    for (i=0; i<N_MAXSOCKETS; i++) {
        if (!sockets[i].valid) {
            sockets[i].valid = true;
            break;
        }
    }
    return i;
}

int i_socket(int domain, int type, int protocol) {
    int i = next_avail();
    if (i == -1) {
        return -1;
    }

    struct socket_impl *s = sockets + i;

    if (domain != AF_INET) return -1;

    // TODO we could validate these inputs
    if (type == SOCK_STREAM) protocol = IPPROTO_TCP;
    if (type == SOCK_DGRAM) protocol = IPPROTO_UDP;

    s->domain = domain;     // AF_INET
    s->type = type;         // SOCK_STREAM, SOCK_DGRAM, or SOCK_RAW
    s->protocol = protocol; // IPPROTO_TCP, IPPROTO_UDP, or IP protocol #
    s->state = REQUESTED;
    return i;
}

int i_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    if (in_addr->sin_family != AF_INET) return -1;

    s->local_ip = in_addr->sin_addr.s_addr;
    s->local_port = in_addr->sin_port;

    pthread_mutex_init(&s->data_mtx, NULL);
    pthread_cond_init(&s->data_cond, NULL);

    s->state = BOUND;
    return 0;
}

int i_listen(int sockfd, int backlog) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    int res = pthread_mutex_init(&s->listen_mtx, NULL);
    if (res != 0) return -1;
    res = pthread_cond_init(&s->listen_cond, NULL);
    if (res != 0) return -1;

    s->state = LISTENING;
    return 0;
}

int i_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    pthread_mutex_lock(&s->listen_mtx);
    pthread_cond_wait(&s->listen_cond, &s->listen_mtx);

    int i = next_avail();
    if (i == -1) return -1;

    struct socket_impl *as = sockets + i;
    as->valid = true;
    as->domain = s->domain;
    as->type = s->type;
    as->protocol = s->protocol;
    as->local_ip = s->local_ip;
    as->local_port = s->local_port;

    as->remote_ip = s->accept_data.remote_ip;
    as->remote_port = s->accept_data.remote_port;
    as->state = OUTBOUND;

    struct sockaddr_in in_addr = {
        .sin_family = AF_INET,
        .sin_port = as->remote_port,
        .sin_addr = {as->remote_ip},
    };

    memcpy(addr, &in_addr, sizeof(in_addr));
    *addrlen = sizeof(in_addr);

    pthread_mutex_unlock(&s->listen_mtx);
    return i;
}

int i_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
    if (in_addr->sin_family != AF_INET) return -1;

    s->remote_ip = in_addr->sin_addr.s_addr;
    s->remote_port = in_addr->sin_port;

    // setup? SYN?

    s->state = OUTBOUND;
    return 0;
}

ssize_t i_send(int sockfd, const void *buf, size_t len, int flags) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    if (s->state != OUTBOUND) return -1;

    return -1; // ETODO
}

ssize_t i_sendto(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    if (s->type != SOCK_DGRAM) {
        return -1; // ETODO;
    }

    struct sockaddr_in *in_addr = (struct sockaddr_in *)dest_addr;
    if (addrlen != sizeof(*in_addr)) return -1;

    int pkt_len = sizeof(struct eth_hdr) +
                  sizeof(struct ip_hdr) + 
                  sizeof(struct udp_pkt) +
                  len;
    void *pkt = malloc(pkt_len);

    int fd = route(in_addr->sin_addr.s_addr);

    struct mac_addr dst_mac = resolve_mac(fd, in_addr->sin_addr.s_addr);

    int index = make_eth_hdr(pkt, dst_mac, ETH_IP);
    struct ip_hdr *ip = pkt + index;
    index += make_ip_hdr(ip, htons(s->ip_id), PROTO_UDP, in_addr->sin_addr.s_addr);
    s->ip_id += 1;
    struct udp_pkt *udp = pkt + index;
    udp->src_port = s->local_port;
    udp->dst_port = in_addr->sin_port;
    udp->len = htons(len + 8);
    udp->checksum = 0; // checksum disabled -- TODO enable
    index += 8;
    void *data = pkt + index;
    memcpy(data, buf, len);
    index += len;

    ip->total_len = htons(index - sizeof(struct eth_hdr));
    place_ip_checksum(ip);

    write_to_wire(fd, pkt, index);
    free(pkt);
    return len;
}

ssize_t i_recv(int sockfd, void *bud, size_t len, int flags) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    return -1; // ETODO
}

ssize_t i_recvfrom(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    pthread_mutex_lock(&s->data_mtx);
    pthread_cond_wait(&s->data_cond, &s->data_mtx);

    struct sockaddr_in *in_addr = (struct sockaddr_in *)src_addr;
    if (*addrlen < sizeof(*in_addr)) return -1;
    in_addr->sin_family = AF_INET;
    in_addr->sin_port = s->pending_remote_port;
    in_addr->sin_addr.s_addr = s->pending_remote_ip;
    *addrlen = sizeof(*in_addr);

    len = (s->pending_data_len < len) ? s->pending_data_len : len;
    memcpy(buf, s->pending_data, len);

    free(s->pending_data);
    s->pending_data = NULL;

    pthread_mutex_unlock(&s->data_mtx);
    return len;
}

int i_close(int sockfd) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;
    
    // teardown connections ?

    s->state = IDLE;
    s->valid = false;
    return 0;
}

//
// DISPATCH
//

void socket_dispatch_udp(struct eth_hdr *eth) {
    printf("dispatching udp\n");
    struct ip_hdr *ip = (void *)eth + sizeof(*eth);
    struct udp_pkt *udp = (void *)ip + sizeof(*ip);
    void *data = (void *)udp + sizeof(*udp);

    int best_match = -1;
    for (int i=0; i<N_MAXSOCKETS; i++) {
        int strength = 0;
        struct socket_impl *s = sockets + i;

        if (!(s->valid)) continue;
        if (!(s->domain == AF_INET)) continue;
        if (!(s->type == SOCK_DGRAM)) continue;
        if (!(s->protocol == IPPROTO_UDP)) continue;

        if (s->local_ip == ip->dst_ip) strength++;
        if (s->local_port == udp->dst_port) strength++;

        if (s->state == BOUND && s->local_ip == 0) strength++;

        if (s->state == OUTBOUND) {
            if (s->remote_ip == ip->src_ip) strength++;
            if (s->remote_port == udp->src_port) strength++;
        }

        if (s->state == BOUND && strength == 2) {
            best_match = i;
            break;
        }

        if (s->state == OUTBOUND && strength == 4) {
            best_match = i;
            break;
        }
    }
    if (best_match == -1) {
        // no matching socket, drop.
        return;
    }
    printf("dispatch found match: %i\n", best_match);
    struct socket_impl *s = sockets + best_match;

    if (s->pending_data) {
        // too slow, drop. (TODO: queue)
        return;
    }

    int len = ntohs(udp->len) - 8;
    s->pending_data = malloc(len);
    s->pending_data_len = len;
    s->pending_remote_ip = ip->src_ip;
    s->pending_remote_port = udp->src_port;
    memcpy(s->pending_data, data, len);

    pthread_mutex_lock(&s->data_mtx);
    pthread_cond_signal(&s->data_cond);
    pthread_mutex_unlock(&s->data_mtx);
}

