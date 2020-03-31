
#ifndef IPSTACK_SOCKET_H
#define IPSTACK_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"

typedef uint32_t be32;
typedef uint16_t be16;

enum socket_state {
    SOCKET_IDLE = 0,
    SOCKET_REQUESTED,
    SOCKET_BOUND,
    SOCKET_LISTENING,
    SOCKET_OUTBOUND,
};

enum tcp_state {
    TCP_S_LISTEN,
    TCP_S_SYN_SENT,
    TCP_S_SYN_RECIEVED,
    TCP_S_ESTABLISHED,
    TCP_S_FIN_WAIT_1,
    TCP_S_FIN_WAIT_2,
    TCP_S_CLOSE_WAIT,
    TCP_S_CLOSING,
    TCP_S_LAST_ACK,
    TCP_S_TIME_WAIT,
    TCP_S_CLOSED,
};

struct accept_data {
    // IPism
    be32 remote_ip;
    uint16_t remote_port;
    uint32_t remote_seq;
};

// consider a rename to "sock"
struct socket_impl {
    bool valid;
    enum socket_state state;

    int domain;
    int type;
    int protocol;

    unsigned int ip_id;

    // IPism
    // NETWORK byte order
    be32 local_ip;
    be16 local_port;
    be32 remote_ip;
    be16 remote_port;

    pthread_mutex_t data_mtx;
    pthread_cond_t data_cond;
    void *pending_data;
    int pending_data_len;
    be32 pending_remote_ip;
    be16 pending_remote_port;

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

void socket_dispatch_udp(struct pkb *);
void socket_dispatch_tcp(struct pkb *);

#endif // IPSTACK_SOCKET_H

