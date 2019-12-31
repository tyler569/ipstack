
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
#include <errno.h>
#include "net.h"

enum socket_state {
    IDLE = 0,
    REQUESTED,
    BOUND,
    LISTENING,
    OUTBOUND,
};

enum tcp_state {
    LISTEN,
    SYN_SENT,
    SYN_RECIEVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED,
};

struct accept_data {
    // IPism
    uint32_t remote_ip;
    uint16_t remote_port;
    uint32_t remote_seq;
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

    pthread_mutex_t data_mtx;
    pthread_cond_t data_cond;
    void *pending_data;
    int pending_data_len;
    uint32_t pending_remote_ip;
    uint16_t pending_remote_port;

    pthread_mutex_t listen_mtx;
    pthread_cond_t listen_cond;
    struct accept_data accept_data;

    // TCP {{
    // HOST byte order
    uint32_t send_seq; // SND.NXT
    uint32_t send_ack; // SND.UNA
    uint32_t recv_seq; // RCV.NXT
    uint16_t window_size;

    char *recv_buffer; // [window]
    char *send_buffer; // for retx

    pthread_mutex_t ack_mtx;
    pthread_cond_t ack_cond;

    enum tcp_state tcp_state;
    // }}
};

void tcp_syn(struct socket_impl *);
void tcp_ack(struct socket_impl *);
void tcp_send(struct socket_impl *, const void *, size_t);
// void tcp_connect(struct socket_impl *);

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
        errno = ENOMEM;
        return -1;
    }

    struct socket_impl *s = sockets + i;

    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

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
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    if (in_addr->sin_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    s->local_ip = in_addr->sin_addr.s_addr;
    s->local_port = in_addr->sin_port;

    pthread_mutex_init(&s->data_mtx, NULL);
    pthread_cond_init(&s->data_cond, NULL);

    s->state = BOUND;
    return 0;

}

int i_listen(int sockfd, int backlog) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    int res = pthread_mutex_init(&s->listen_mtx, NULL);
    if (res != 0) {
        errno = EFAULT;
        return -1;
    }

    pthread_cond_init(&s->listen_cond, NULL);
    if (res != 0) {
        errno = EFAULT;
        return -1;
    }

    s->state = LISTENING;
    return 0;
}

int i_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    if (!(s->type == SOCK_STREAM)) {
        errno = EOPNOTSUPP;
        return -1;
    }

    pthread_mutex_lock(&s->listen_mtx);
    pthread_cond_wait(&s->listen_cond, &s->listen_mtx);

    int i = next_avail();
    if (i == -1) {
        errno = ENOMEM;
        return -1;
    }

    struct socket_impl *as = sockets + i;

    memcpy(as, s, sizeof(struct socket_impl));
    as->state = OUTBOUND;
    as->tcp_state = SYN_RECIEVED;
    as->remote_ip = as->accept_data.remote_ip;
    as->remote_port = as->accept_data.remote_port;
    as->recv_seq = as->accept_data.remote_seq;

    struct sockaddr_in in_addr = {
        .sin_family = AF_INET,
        .sin_port = as->remote_port,
        .sin_addr = {as->remote_ip},
    };

    memcpy(addr, &in_addr, sizeof(in_addr));
    *addrlen = sizeof(in_addr);

    tcp_ack(s);

    pthread_mutex_unlock(&s->listen_mtx);
    return i;
}

int i_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
    if (in_addr->sin_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    s->remote_ip = in_addr->sin_addr.s_addr;
    s->remote_port = in_addr->sin_port;
    s->state = OUTBOUND;

    if (s->protocol == IPPROTO_TCP) {
        pthread_mutex_lock(&s->ack_mtx);
        tcp_syn(s); // + timeout

        pthread_cond_wait(&s->ack_cond, &s->ack_mtx);
        pthread_mutex_unlock(&s->ack_mtx);

        if (s->tcp_state != ESTABLISHED) {
            errno = ECONNREFUSED;
            return -1;
        }
    }

    return 0;
}

ssize_t i_send(int sockfd, const void *buf, size_t len, int flags) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    if (s->state != OUTBOUND) {
        errno = EDESTADDRREQ;
        return -1;
    }

    if (s->type == SOCK_DGRAM) {
        errno = 1000;
        // UDP TODO
        return -1;
    }

    if (s->type == SOCK_STREAM) {
        tcp_send(s, buf, len);
    }
    return len;
}

ssize_t i_sendto(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    if (s->type != SOCK_DGRAM) {
        errno = EFAULT; // TODO
        return -1;
    }

    struct sockaddr_in *in_addr = (struct sockaddr_in *)dest_addr;
    if (addrlen != sizeof(*in_addr)) {
        errno = EFAULT; // TODO ? How do you handle this?
        return -1;
    }

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

    ip->total_length = htons(index - sizeof(struct eth_hdr));
    place_ip_checksum(ip);

    write_to_wire(fd, pkt, index);
    free(pkt);
    return len;
}

ssize_t i_recv(int sockfd, void *bud, size_t len, int flags) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    errno = 1000;
    return -1; // ETODO
}

ssize_t i_recvfrom(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) {
        errno = ENOTSOCK;
        return -1;
    }

    pthread_mutex_lock(&s->data_mtx);
    pthread_cond_wait(&s->data_cond, &s->data_mtx);

    struct sockaddr_in *in_addr = (struct sockaddr_in *)src_addr;
    if (*addrlen < sizeof(*in_addr)) {
        errno = EFAULT;
        return -1;
    }
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

size_t tcp_len(tcp_pkt *tcp) {
    return tcp->offset * 4;
}

void tcp_syn(struct socket_impl *s) {
    s->send_seq = rand();
    s->send_ack = 0;
    s->recv_seq = 0;

    int fd = route(s->remote_ip);
    int len = sizeof(struct eth_hdr) +
              sizeof(struct ip_hdr) +
              sizeof(struct tcp_pkt);
    void *pkt = malloc(len);
    struct eth_hdr *eth = pkt;
    struct mac_addr dst_mac = resolve_mac(fd, s->remote_ip);
    make_eth_hdr(pkt, dst_mac, ETH_IP);
    struct ip_hdr *ip = (void *)(eth + 1);
    make_ip_hdr(ip, htons(s->ip_id), PROTO_TCP, s->remote_ip);
    s->ip_id += 1;
    struct tcp_pkt *tcp = (void *)(ip + 1);
    tcp->src_port = s->local_port;
    tcp->dst_port = s->remote_port;
    tcp->seq = htonl(s->send_seq);
    tcp->ack = 0;
    tcp->offset = 5;
    tcp->_reserved = 0;
    tcp->_reserved2 = 0;
    tcp->f_urg = 0;
    tcp->f_ack = 0;
    tcp->f_psh = 0;
    tcp->f_rst = 0;
    tcp->f_syn = 1;
    tcp->f_fin = 0;
    tcp->window = htons(0x1000);
    tcp->checksum = 0;
    tcp->urg_ptr = 0;
    ip->total_length = htons(len - sizeof(struct eth_hdr));
    place_tcp_checksum(ip);
    place_ip_checksum(ip);

    write_to_wire(fd, pkt, len);

    s->send_seq += 1; // SYN is ~ 1 byte.
    s->tcp_state = SYN_SENT;
}

void tcp_ack(struct socket_impl *s) {
    int fd = route(s->remote_ip);
    int len = sizeof(struct eth_hdr) +
              sizeof(struct ip_hdr) +
              sizeof(struct tcp_pkt);
    void *pkt = malloc(len);
    struct eth_hdr *eth = pkt;
    struct mac_addr dst_mac = resolve_mac(fd, s->remote_ip);
    make_eth_hdr(pkt, dst_mac, ETH_IP);
    struct ip_hdr *ip = (void *)(eth + 1);
    make_ip_hdr(ip, htons(s->ip_id), PROTO_TCP, s->remote_ip);
    s->ip_id += 1;
    struct tcp_pkt *tcp = (void *)(ip + 1);
    // COPYPASTA from tcp_syn
    tcp->src_port = s->local_port;
    tcp->dst_port = s->remote_port;
    tcp->seq = htonl(s->send_seq);
    tcp->ack = htonl(s->recv_seq);
    tcp->offset = 5;
    tcp->_reserved = 0;
    tcp->_reserved2 = 0;
    tcp->f_urg = 0;
    tcp->f_ack = 1;
    tcp->f_psh = 0;
    tcp->f_rst = 0;
    if (s->tcp_state == LISTEN) {
        tcp->f_syn = 1;
    } else {
        tcp->f_syn = 0;
    }
    tcp->f_fin = 0;
    tcp->window = htons(0x1000);
    tcp->checksum = 0;
    tcp->urg_ptr = 0;
    ip->total_length = htons(len - sizeof(struct eth_hdr));
    place_tcp_checksum(ip);
    place_ip_checksum(ip);

    write_to_wire(fd, pkt, len);

    if (tcp->f_syn || tcp->f_fin) {
        s->send_seq += 1;
    }
}

void tcp_send(struct socket_impl *s, const void *data, size_t len) {
    int fd = route(s->remote_ip);
    int plen = sizeof(struct eth_hdr) +
              sizeof(struct ip_hdr) +
              sizeof(struct tcp_pkt) +
              len;
    void *pkt = malloc(plen);
    struct eth_hdr *eth = pkt;
    struct mac_addr dst_mac = resolve_mac(fd, s->remote_ip);
    make_eth_hdr(pkt, dst_mac, ETH_IP);
    struct ip_hdr *ip = (void *)(eth + 1);
    make_ip_hdr(ip, htons(s->ip_id), PROTO_TCP, s->remote_ip);
    s->ip_id += 1;
    struct tcp_pkt *tcp = (void *)(ip + 1);
    void *pdata = (void *)(tcp + 1);
    // COPYPASTA from tcp_syn
    tcp->src_port = s->local_port;
    tcp->dst_port = s->remote_port;
    tcp->seq = htonl(s->send_seq);
    tcp->ack = htonl(s->recv_seq);
    tcp->offset = 5;
    tcp->_reserved = 0;
    tcp->_reserved2 = 0;
    tcp->f_urg = 0;
    tcp->f_ack = 1;
    tcp->f_psh = 0;
    tcp->f_rst = 0;
    tcp->f_syn = 0;
    tcp->f_fin = 0;
    tcp->window = htons(0x1000);
    tcp->checksum = 0;
    tcp->urg_ptr = 0;
    ip->total_length = htons(plen - sizeof(struct eth_hdr));

    memcpy(pdata, data, len);

    place_tcp_checksum(ip);
    place_ip_checksum(ip);

    write_to_wire(fd, pkt, plen);

    s->send_seq += len;
}

void require_that(bool x) {}

void socket_dispatch_tcp(struct eth_hdr *eth) {
    struct ip_hdr *ip = (void *)(eth + 1);
    struct tcp_pkt *tcp = (void *)(ip + 1);

    int best_match = -1;
    for (int i=0; i<N_MAXSOCKETS; i++) {
        int strength = 0;
        struct socket_impl *s = sockets + i;

        if (!(s->valid)) continue;
        if (!(s->domain == AF_INET)) continue;
        if (!(s->type == SOCK_STREAM)) continue;
        if (!(s->protocol == IPPROTO_TCP)) continue;

        if (s->local_ip == ip->dst_ip) strength++;
        if (s->local_port == tcp->dst_port) strength++;

        if (s->state == LISTENING && s->local_ip == 0) strength++;

        if (s->state == OUTBOUND) {
            if (s->remote_ip == ip->src_ip) strength++;
            if (s->remote_port == tcp->src_port) strength++;
        }

        if (s->state == LISTENING && strength == 2) {
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

    uint16_t ip_len = ntohs(ip->total_length);
    uint32_t tcp_rseq = ntohl(tcp->seq);
    uint32_t tcp_rack = ntohl(tcp->ack);

    // ACK sequence update
    if (tcp->f_ack) {
        s->send_ack = tcp_rack;
    }

    // SYN -> RST
    if (s->tcp_state == SYN_SENT && tcp->f_rst) {
        s->tcp_state = CLOSED;
        pthread_mutex_lock(&s->ack_mtx);
        pthread_cond_signal(&s->ack_cond);
        pthread_mutex_unlock(&s->ack_mtx);
    }

    // SYN -> SYN/ACK
    if (s->tcp_state == SYN_SENT && tcp->f_syn && tcp->f_ack) {
        require_that(s->send_ack == s->send_seq);
        s->recv_seq = tcp_rseq + 1; // SYN is ~ 1 byte
        tcp_ack(s);

        s->tcp_state = ESTABLISHED;

        pthread_mutex_lock(&s->ack_mtx);
        pthread_cond_signal(&s->ack_cond);
        pthread_mutex_unlock(&s->ack_mtx);
    }

    uint32_t new_seq = tcp_rseq + ip_len - sizeof(ip_hdr) - tcp_len(tcp);
    if (tcp->f_fin) {
        new_seq += 1;
    }

    if (new_seq > s->recv_seq) { // TODO MODULO 2**32
        // TODO: save data
        // TODO: ack data
        // TODO: make available to application
        printf("TCP: data available, just acking.\n");
        s->recv_seq = new_seq;
        tcp_ack(s);
    }

    // RST
    if (tcp->f_rst) {
        printf("TCP RST\n");
        return;
    }

    if (s->state == LISTENING) {
        s->accept_data.remote_ip = ip->src_ip;
        s->accept_data.remote_port = tcp->src_port;
        s->accept_data.remote_seq = tcp->seq;

        pthread_mutex_lock(&s->listen_mtx);
        pthread_cond_signal(&s->listen_cond);
        pthread_mutex_unlock(&s->listen_mtx);

        // accept runs the syn/ack
    }

    // segment things
    // TODO
}

