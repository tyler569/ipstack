
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include "list.h"
#include "net.h"

const char *if_name = "tap0";

int tun_alloc(const char *tun_name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        printf("Error: %s\n", strerror(errno));
        return -1;
    }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);

    int err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0) {
        printf("Error: %s\n", strerror(errno));
        close(fd);
        return err;
    }

    return fd;
}

bool mac_eq(struct mac_address a, struct mac_address b) {
    return memcmp(&a, &b, 6) == 0;
}

struct route route_table[1];

be32 best_route(be32 address) {
    unsigned long best_prefix = 0;
    be32 best_next_hop = 0;
    for (int i=0; i<ARRAY_LEN(route_table); i++) {
        if ((address & route_table[i].netmask) == route_table[i].prefix) {
            if (route_table[i].prefix >= best_prefix) {
                best_next_hop = route_table[i].next_hop;
                best_prefix = route_table[i].prefix;
            }
        }
    }

    return best_next_hop;
}

struct pkb *new_pk() {
    struct pkb *new_pk = calloc(1, sizeof(struct pkb) + ETH_MTU);
    new_pk->length = -1;
    new_pk->from = NULL;
    new_pk->refcount = 1;
    return new_pk;
}

void free_pk(struct pkb *pk) {
    pk_decref(pk);
    if (pk->refcount <= 0) {
        free(pk);
    }
}

void pk_incref(struct pkb *pk) {
    pk->refcount++;
}

void pk_decref(struct pkb *pk) {
    pk->refcount--;
}

struct ethernet_header *eth_hdr(struct pkb *pk) {
    return (struct ethernet_header *)&pk->buffer;
}

struct arp_header *arp_hdr(struct pkb *pk) {
    return (struct arp_header *)(pk->buffer + sizeof(struct ethernet_header));
}

struct ip_header *ip_hdr(struct pkb *pk) {
    return (struct ip_header *)(pk->buffer + sizeof(struct ethernet_header));
}

struct udp_header *udp_hdr(struct ip_header *ip) {
    return (struct udp_header *)((char *)ip + (ip->header_length * 4));
}

struct tcp_header *tcp_hdr(struct ip_header *ip) {
    return (struct tcp_header *)((char *)ip + (ip->header_length * 4));
}

struct icmp_header *icmp_hdr(struct ip_header *ip) {
    return (struct icmp_header *)((char *)ip + (ip->header_length * 4));
}

int is_arp(struct pkb *pk) {
    struct ethernet_header *eth = eth_hdr(pk);
    return htons(eth->ethertype) == ETH_ARP;
}

int is_ip(struct pkb *pk) {
    struct ethernet_header *eth = eth_hdr(pk);
    return htons(eth->ethertype) == ETH_IP;
}

int is_udp(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);
    return is_ip(pk) && ip->proto == PROTO_UDP;
}

int is_tcp(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);
    return is_ip(pk) && ip->proto == PROTO_TCP;
}

int is_icmp(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);
    return is_ip(pk) && ip->proto == PROTO_ICMP;
}

int ip_len(struct pkb *pk) {
    assert(is_ip(pk));

    struct ip_header *ip = ip_hdr(pk);
    return ntohs(ip->total_length);
}

int tcp_len(struct pkb *pk) {
    assert(is_tcp(pk));

    struct ip_header *ip = ip_hdr(pk);
    struct tcp_header *tcp = tcp_hdr(ip);

    return ntohs(ip->total_length) -
           ip->header_length * 4 -
           tcp->offset * 4;
}

void *tcp_data(struct pkb *pk) {
    assert(is_tcp(pk));

    struct ip_header *ip = ip_hdr(pk);
    struct tcp_header *tcp = tcp_hdr(ip);

    return (char *)tcp + tcp->offset * 4;
}

int udp_len(struct pkb *pk) {
    assert(is_udp(pk));

    struct ip_header *ip = ip_hdr(pk);

    return ntohs(ip->total_length) -
           sizeof(struct ip_header) -
           sizeof(struct udp_header);
}

void *udp_data(struct pkb *pk) {
    assert(is_udp(pk));

    struct ip_header *ip = ip_hdr(pk);
    struct udp_header *udp = udp_hdr(ip);

    return udp->data;
}

void echo_icmp(struct pkb *pk) {
    struct pkb *resp = new_pk();
    reply_icmp(resp, pk);
    dispatch(resp);
    free_pk(resp);
}

void reply_icmp(struct pkb *resp, struct pkb *pk) {
    struct ethernet_header *r_eth = eth_hdr(resp);
    r_eth->ethertype = htons(ETH_IP);

    struct ip_header *r_ip = ip_hdr(resp);
    struct ip_header *s_ip = ip_hdr(pk);

    r_ip->version = 4;
    r_ip->header_length = 5;
    r_ip->dscp = 0;
    r_ip->total_length = 0;
    r_ip->id = s_ip->id;
    r_ip->flags_frag = htons(0x4000); // DNF - make this better
    r_ip->ttl = 64;
    r_ip->proto = IPPROTO_ICMP;
    r_ip->source_ip = s_ip->destination_ip;
    r_ip->destination_ip = s_ip->source_ip;

    struct icmp_header *r_icmp = icmp_hdr(r_ip);
    struct icmp_header *s_icmp = icmp_hdr(s_ip);

    size_t icmp_data_length = htons(s_ip->total_length) -
                              sizeof(struct ip_header) - 
                              sizeof(struct icmp_header);

    r_icmp->type = ICMP_ECHO_RESP;
    r_icmp->code = 0;
    r_icmp->checksum = 0;
    r_icmp->ident = s_icmp->ident;
    r_icmp->sequence = s_icmp->sequence;
    r_icmp->timestamp = s_icmp->timestamp;
    r_icmp->timestamp_low = s_icmp->timestamp_low;

    memcpy(r_icmp->data, s_icmp->data, icmp_data_length);

    r_ip->total_length = htons(
            sizeof(struct ip_header) +
            sizeof(struct icmp_header) +
            icmp_data_length
    );

    resp->length = ip_len(resp) + sizeof(struct ethernet_header);

    ip_checksum(resp);
    icmp_checksum(resp);
}

void make_udp(struct socket_impl *sock, struct pkb *pk,
        struct sockaddr_in *d_addr, const void *data, size_t len) {
    struct ethernet_header *r_eth = eth_hdr(pk);
    r_eth->ethertype = htons(ETH_IP);

    struct ip_header *ip = ip_hdr(pk);

    ip->version = 4;
    ip->header_length = 5;
    ip->dscp = 0;
    ip->total_length = htons(
        sizeof(struct ip_header) + sizeof(struct udp_header) + len
    );
    ip->id = ntohs(sock->ip_id);
    ip->flags_frag = htons(0x4000); // DNF - make this better
    ip->ttl = 64;
    ip->proto = IPPROTO_UDP;
    ip->source_ip = sock->local_ip;

    if (d_addr) {
        ip->destination_ip = d_addr->sin_addr.s_addr;
    } else {
        ip->destination_ip = sock->remote_ip;
    }

    struct udp_header *udp = udp_hdr(ip);

    udp->length = htons(len + sizeof(struct udp_header));
    udp->checksum = 0;
    udp->source_port = sock->local_port;

    if (d_addr) {
        udp->destination_port = d_addr->sin_port;
    } else {
        udp->destination_port = sock->remote_port;
    }

    memcpy(udp->data, data, len);

    pk->length = ip_len(pk) + sizeof(struct ethernet_header);

    ip_checksum(pk);
    udp_checksum(pk);
}

void make_tcp(struct socket_impl *s, struct pkb *pk, int flags,
        const void *data, size_t len) {
    struct ethernet_header *eth = eth_hdr(pk);
    eth->ethertype = htons(ETH_IP);

    struct ip_header *ip = ip_hdr(pk);
    ip->version = 4;
    ip->header_length = 5;
    ip->dscp = 0;
    ip->id = ntohs(s->ip_id);
    ip->flags_frag = htons(0x4000); // DNF
    ip->ttl = 64;
    ip->proto = IPPROTO_TCP;
    ip->source_ip = s->local_ip;
    ip->destination_ip = s->remote_ip;
    ip->total_length = htons(
            sizeof(struct ip_header) +
            sizeof(struct tcp_header) +
            len
    );

    struct tcp_header *tcp = tcp_hdr(ip);
    tcp->source_port = s->local_port;
    tcp->destination_port = s->remote_port;
    tcp->seq = htonl(s->send_seq);
    if (flags & TCP_ACK) {
        tcp->ack = htonl(s->recv_seq);
    } else {
        tcp->ack = 0;
    }
    tcp->offset = 5;
    tcp->_reserved = 0;
    tcp->_reserved2 = 0;
    tcp->f_urg = ((flags & TCP_URG) > 0);
    tcp->f_ack = ((flags & TCP_ACK) > 0);
    tcp->f_psh = ((flags & TCP_PSH) > 0);
    tcp->f_rst = ((flags & TCP_RST) > 0);
    tcp->f_syn = ((flags & TCP_SYN) > 0);
    tcp->f_fin = ((flags & TCP_FIN) > 0);
    tcp->window = htons(0x1000);
    tcp->checksum = 0;
    tcp->urg_ptr = 0;

    memcpy(tcp->data, data, len);

    pk->length = ip_len(pk) + sizeof(struct ethernet_header);

    tcp_checksum(pk);
    ip_checksum(pk);
}

void dispatch(struct pkb *pk) {
    printf("dispatching %p\n", pk);
    assert(is_ip(pk));

    struct ip_header *ip = ip_hdr(pk);
    be32 next_hop = best_route(ip->destination_ip);

    struct net_if *intf = interface_containing(next_hop);
    if (!intf) {
        printf("null interface is bad\n");
        return;
    }
    if (next_hop == intf->ip) {
        // it was me all along!
        printf("TODO: handle packets to own actual interface\n");
        return;
    }

    // enable bind to 0.0.0.0
    // This does not work yet - the checksums are wrong
    if (ip->source_ip == 0) {
        ip->source_ip = intf->ip;

        if (is_udp(pk)) {
            udp_checksum(pk);
        }
        if (is_tcp(pk)) {
            tcp_checksum(pk);
        }
        if (is_icmp(pk)) {
            icmp_checksum(pk);
        }

        ip_checksum(pk);
    }

    // printf("next hop is %x\n", next_hop);

    struct mac_address d = arp_cache_get(intf, next_hop);

    // printf("next hop is at ");
    // print_mac_address(d);
    // printf("\n");

    if (!mac_eq(d, zero_mac)) {
        struct ethernet_header *eth = eth_hdr(pk);
        eth->source_mac = intf->mac_address;
        eth->destination_mac = d;

        intf->write_to_wire(intf, pk);
    } else {
        query_for(intf, next_hop, pk);
    }
}

void arp_cache_put(struct net_if *intf, be32 ip, struct mac_address mac) {
    struct arp_cache *ac = &intf->arp_cache;

    for (int i=0; i<ARP_CACHE_LEN; i++) {
        if (ac->cl[i].ip == 0) {
            ac->cl[i].ip = ip;
            ac->cl[i].mac = mac;
        }
    }

    struct pending_mac_query *q;
    list_foreach(&intf->pending_mac_queries, q, queries) {
        if (q->ip == ip) {
            // This might not be safe if I continued iterating (not sure),
            // but is probably fine because I break if I ever get here
            list_remove(&q->queries);

            struct pkb *pending_pk;
            while ((pending_pk = list_pop_front(struct pkb, &q->pending_pks, queue))) {
                dispatch(pending_pk);
                free(pending_pk);
            }

            free(q);

            break;
        }
    }
}

struct mac_address arp_cache_get(struct net_if *intf, be32 ip) {
    struct arp_cache *ac = &intf->arp_cache;

    for (int i=0; i<ARP_CACHE_LEN; i++) {
        if (ip && ac->cl[i].ip == ip) {
            return ac->cl[i].mac;
        }
    }

    return zero_mac;
}

void query_for(struct net_if *intf, be32 address, struct pkb *pk) {
    struct pending_mac_query *q;
    list_foreach(&intf->pending_mac_queries, q, queries) {
        if (address == q->ip) {
            if (pk) {
                pk_incref(pk);
                list_append(&q->pending_pks, pk, queue);
            }
            return;
        }
    }

    // The query has not been sent

    q = malloc(sizeof(*q)); // freed in arp_cache_put

    q->ip = address;
    q->mac = zero_mac;
    q->attempts = 1;

    list_init(&q->pending_pks);

    printf("appending %p to a queue\n", pk);

    pk_incref(pk);
    list_append(&q->pending_pks, pk, queue);
    list_append(&intf->pending_mac_queries, q, queries);

    struct pkb *arp_hdr = new_pk();
    arp_query(arp_hdr, address, intf);
    intf->write_to_wire(intf, arp_hdr);
}


void arp_query(struct pkb *pk, be32 address, struct net_if *intf) {
    struct ethernet_header *eth = eth_hdr(pk);
    eth->destination_mac = broadcast_mac;
    eth->source_mac = intf->mac_address;
    eth->ethertype = htons(ETH_ARP);

    struct arp_header *r_arp = arp_hdr(pk);
    r_arp->hw_type = htons(1);      // eth_hdr
    r_arp->proto = htons(0x0800);   // ip_hdr
    r_arp->hw_size = 6;
    r_arp->proto_size = 4;
    r_arp->op = htons(ARP_REQ);
    r_arp->sender_mac = intf->mac_address;
    r_arp->sender_ip = intf->ip;
    r_arp->target_mac = zero_mac;
    r_arp->target_ip = address;

    pk->length = sizeof(struct ethernet_header) +
                 sizeof(struct arp_header);
}


struct mac_address mac_from_str_trad(char *mac_str) {
    struct mac_address res = {0};
    char *end;
    for (int i=0; i<6; i++) {
        res.data[i] = strtol(mac_str, &end, 16);
        if (end - mac_str != 2) {
            printf("Invalid MAC address at '%s' !\n", mac_str);
            exit(0);
        }

        // TODO: make sure the seperators are as expected.
        // Not really the end of the world, since if they're valid numbers the
        // != 2 check will already kill it there.

        mac_str = end + 1;
    }
    return res;
}

struct mac_address mac_from_str(char *mac_str) {
    // accepts 3 formats:
    //  no punctuation: 00180a334455
    //  traditional   : 00:18:0a:33:44:55
    //  cisco-style   : 0018.0a22.4455

    switch (strlen(mac_str)) {
    case 12:
        printf("That style is TODO\n");
        break;
    case 14:
        printf("That style is TODO\n");
        break;
    case 17:
        return mac_from_str_trad(mac_str);
        break;
    default:
        printf("Invalid MAC address\n");
        break;
    }
    exit(1);
}

void print_mac_address(struct mac_address mac) {
    printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", 
            mac.data[0], mac.data[1], mac.data[2],
            mac.data[3], mac.data[4], mac.data[5]);
}


uint32_t ip_from_str(char *ip_str) {
    uint32_t ip = 0;
    char *end;

    for (int i=0; i<4; i++) {
        ip <<= 8;
        ip += strtol(ip_str, &end, 10);
        if (ip_str == end) {
            printf("Error parsing that IP at '%s' !\n", ip_str);
            exit(0);
        }
        ip_str = end + 1;
    }

    return ip;
}

void print_ip_address(uint32_t ip) {
    printf("%i.%i.%i.%i",
        (ip) & 0xff,
        (ip >> 8) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 24) & 0xff
    );
}

void print_arp_pkt(struct pkb *pk) {
    struct arp_header *arp = arp_hdr(pk);

    int op = ntohs(arp->op);
    if (op == ARP_REQ) {
        printf("arp_hdr Request who-has ");
        print_ip_address(arp->target_ip);
        printf(" tell ");
        print_ip_address(arp->sender_ip);
        printf("\n");
    } else if (op == ARP_RESP) {
        printf("arp_hdr Responce ");
        print_ip_address(arp->sender_ip);
        printf(" is-at ");
        print_mac_address(arp->sender_mac);
        printf("\n");
    } else {
        printf("Unrecognised arp_hdr OP: %i\n", ntohs(arp->op));
    }
}

void ip_checksum(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);

    uint16_t *ip_chunks = (uint16_t *)ip;
    uint32_t checksum32 = 0;
    for (int i=0; i<ip->header_length*2; i+=1) {
        checksum32 += ip_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    ip->header_checksum = ~checksum;
}

struct udp_pseudoheader {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t _zero;
    uint8_t protocol;
    int16_t udp_length;
};

void udp_checksum(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);
    struct udp_header *udp = udp_hdr(ip);

    int length = ntohs(ip->total_length);
    int n_bytes = length - sizeof(struct ip_header);

    struct udp_pseudoheader t = {
        ip->source_ip,
        ip->destination_ip,
        0,
        PROTO_UDP,
        htons(n_bytes),
    };

    uint32_t sum = 0;
    uint16_t *c = (uint16_t *)&t;
    for (int i=0; i<sizeof(t)/2; i++) {
        sum += c[i];
    }

    c = (uint16_t *)udp;
    for (int i=0; i<n_bytes/2; i++) {
        sum += c[i];
    }

    if (n_bytes % 2 != 0) {
        uint16_t last = ((uint8_t *)ip)[length-1];
        sum += last;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    udp->checksum = ~(uint16_t)sum;
}

struct tcp_pseudoheader {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t _zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

void tcp_checksum(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);
    struct tcp_header *tcp = tcp_hdr(ip);

    int length = ntohs(ip->total_length);
    int n_bytes = length - sizeof(struct ip_header);

    struct tcp_pseudoheader t = {
        ip->source_ip,
        ip->destination_ip,
        0,
        PROTO_TCP,
        htons(n_bytes),
    };

    uint32_t sum = 0;
    uint16_t *c = (uint16_t *)&t;
    for (int i=0; i<sizeof(t)/2; i++) {
        sum += c[i];
    }

    c = (uint16_t *)tcp;
    for (int i=0; i<n_bytes/2; i++) {
        sum += c[i];
    }

    if (n_bytes % 2 != 0) {
        uint16_t last = ((uint8_t *)ip)[length-1];
        sum += last;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    tcp->checksum = ~(uint16_t)sum;
}   

void icmp_checksum(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);
    struct icmp_header *icmp = icmp_hdr(ip);

    size_t extra_len = ntohs(ip->total_length) -
                        sizeof(struct ip_header) -
                        sizeof(struct icmp_header);

    uint16_t *icmp_chunks = (uint16_t *)icmp;
    uint32_t checksum32 = 0;
    for (int i=0; i<(sizeof(struct icmp_header) + extra_len)/2; i+=1) {
        checksum32 += icmp_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    icmp->checksum = ~checksum;
}

size_t linux_write_to_wire(struct net_if *intf, struct pkb *pk) {
    int fd = intf->fd;
    long len;
    void *buf = pk->buffer;

    struct ip_header *ip;

    if (pk->length > 0) {
        len = pk->length;
    } else if ((ip = ip_hdr(pk))) {
        len = ntohs(ip->total_length) + sizeof(struct ethernet_header);
    } else {
        printf("length unknown for pkb!\n");
        return -1;
    }

    // printf("Sending this:\n");
    // for (int i=0; i<len; i++) {
    //     printf("%02hhx ", ((uint8_t *)buf)[i]);
    // }
    // printf("\n");

    size_t written_len = write(fd, buf, len);

    // printf("Wrote %li (%s)\n", len, strerror(errno));
    return written_len;
}

void arp_reply(struct pkb *resp, struct pkb *pk) {
    struct ethernet_header *eth = eth_hdr(resp);
    struct arp_header *s_arp = arp_hdr(pk);
    struct arp_header *r_arp = arp_hdr(resp);

    eth->source_mac = pk->from->mac_address;
    eth->destination_mac = s_arp->sender_mac;
    eth->ethertype = htons(ETH_ARP);

    r_arp->hw_type = htons(1);      // eth_hdr
    r_arp->proto = htons(0x0800);   // ip_hdr
    r_arp->hw_size = 6;
    r_arp->proto_size = 4;
    r_arp->op = htons(ARP_RESP);
    r_arp->sender_mac = pk->from->mac_address;
    r_arp->sender_ip = pk->from->ip;
    r_arp->target_mac = s_arp->sender_mac;
    r_arp->target_ip = s_arp->sender_ip;

    resp->length = sizeof(struct ethernet_header) +
                   sizeof(struct arp_header);
}

void process_arp_packet(struct pkb *pk) {
    // print_arp_pkt(pk);
    struct arp_header *arp = arp_hdr(pk);
    arp_cache_put(pk->from, arp->sender_ip, arp->sender_mac);

    // printf("arp: target is %#x\n", arp->target_ip);

    if (ntohs(arp->op) == ARP_REQ && arp->target_ip == pk->from->ip) {
        struct pkb *resp = new_pk();
        arp_reply(resp, pk);
        pk->from->write_to_wire(pk->from, resp);
        free_pk(resp);
    }
}

void process_ip_packet(struct pkb *pk) {
    struct ip_header *ip = ip_hdr(pk);

    // printf("IP detected, next type %#02hhx\n", ip->proto);
    if (ip->destination_ip != pk->from->ip) {
        // printf("Not for my IP, ignoring\n");
        return;
    }
    
    switch (ip->proto) {
    case PROTO_ICMP:
        echo_icmp(pk);
        break;
    case PROTO_UDP:
        socket_dispatch_udp(pk);
        break;
    case PROTO_TCP:
        socket_dispatch_tcp(pk);
        break;
    default:
        // printf("Unknown IP protocol %i\n", ip->proto);
        break;
    }
}

void process_ethernet(struct pkb *pk) {
    struct ethernet_header *eth = eth_hdr(pk);
    struct mac_address dst_mac = eth->destination_mac;
    struct mac_address my_mac = pk->from->mac_address;

    if (mac_eq(dst_mac, my_mac) != 0 && mac_eq(dst_mac, broadcast_mac) != 0) {
        // printf("Not for my MAC addr, ignoring\n");
        return;
    }

    switch (ntohs(eth->ethertype)) {
    case ETH_ARP:
        process_arp_packet(pk);
        break;
    case ETH_IP:
        process_ip_packet(pk);
        break;
    default:
        // printf("Unknown ethertype %#06hx\n", ntohs(eth->ethertype));
        break;
    }
}

struct net_if interfaces[] = {
    {
        .mac_address = {{0x02, 0x00, 0x00, 0x12, 0x34, 0x56}},
        .ip = 0x02011fac,
        .netmask = 0x00ffffff,
        .fd = -1,
        .arp_cache = {},
        .pending_mac_queries = {0},
        .write_to_wire = linux_write_to_wire,
    },
};

struct net_if *interface_containing(be32 ip) {
    if ((ip & interfaces[0].netmask) == 
        (interfaces[0].ip & interfaces[0].netmask)) {

        return &interfaces[0];
    } else {
        return NULL;
    }
}

struct route route_table[] = {
    {0, 0, 0x01011fac}, // 0.0.0.0/0 -> 172.31.1.1
};

int main() {
    int fd = tun_alloc(if_name);
    if (fd < 0) {
        perror("tun_alloc");
    }

    interfaces[0].fd = fd;
    list_init(&interfaces[0].pending_mac_queries);

    pthread_t udp_echo_th;
    int *uport = malloc(sizeof(int));
    *uport = 1100;
    void *udp_echo(void *);
    pthread_create(&udp_echo_th, NULL, udp_echo, uport);

    pthread_t tcp_out_th;
    int *tport = malloc(sizeof(int));
    *tport = 1101;
    void *tcp_out(void *);
    pthread_create(&tcp_out_th, NULL, tcp_out, tport);

    pthread_t tcp_echo_th;
    int *teport = malloc(sizeof(int));
    *teport = 1199;
    void *tcp_echo(void *);
    pthread_create(&tcp_echo_th, NULL, tcp_echo, teport);

    while (true) {
        struct pkb *pk = new_pk();

        int count = read(fd, pk->buffer, ETH_MTU);
        if (count <= 0) {
            perror("read interface");
            exit(1);
        }

        pk->from = &interfaces[0];
        pk->length = count;

        process_ethernet(pk);

        free_pk(pk);
    }
}

