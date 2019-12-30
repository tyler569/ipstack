
#include <sys/types.h>
#include <sys/socket.h>

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

    // IPism
    // NETWORK byte order
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;

    pthread_mutex_t listen_mtx;
    pthread_cond_t listen_cond;
    struct accept_data accept_data;
};

#deifne N_MAXSOCKETS 256

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
    if (type == SOCK_DGRAM) protocol = IPPROTO_UCP;

    s->domain = domain;      // AF_INET
    s->type = type;         // SOCK_STREAM, SOCK_DGRAM, or SOCK_RAW
    s->protocol = protocol; // IPPROTO_TCP, IPPROTO_UDP, or IP protocol #
    s->state = REQUESTED;
}

int i_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
    if (in_addr->sin_family != AF_INET) return -1;

    s->local_ip = in_addr->sin_addr;
    s->local_port = in_addr->sin_port;

    s->state = BOUND;
}

int i_listen(int sockfd, int backlog) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    s->listen_mtx = PTHREAD_MUTEX_INITIALIZER;
    s->listen_cond = PTHREAD_COND_INITIALIZER;

    s->state = LISTENING;
}

int i_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    s->listen_mtx = PTHREAD_MUTEX_INITIALIZER;
    s->listen_cond = PTHREAD_COND_INITIALIZER;

    pthread_mutex_lock(&s->listen_mtx);
    pthread_cond_wait(&s->listen_wait, &s->listen_mtx);

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
        .bin_family = AF_INET,
        .sin_port = as->remote_port,
        .sin_addr = as->remote_ip,
    };

    memcpy(addr, in_addr, sizeof(in_addr));
    *addrlen = sizeof(in_addr);

    pthread_mutex_unlock(&s->listen_mtx);
    return i;
}

int i_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;

    const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
    if (in_addr->sin_family != AF_INET) return -1;

    s->remote_ip = in_addr->sin_addr;
    s->remote_port = in_addr->sin_port;

    // setup? SYN?

    s->state = OUTBOUND;
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

    // DGRAM ONLY therefore UDP ONLY
    return -1; // ETODO
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

    return -1; // ETODO
}
int i_close(int sockfd) {
    struct socket_impl *s = sockets + sockfd;
    if (!s->valid) return -1;
    
    // teardown connections ?

    s->state = IDLE;
    s->valid = false;
}

