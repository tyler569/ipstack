
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
#include "net.h"
#include "list.h"
// #include "socket.h"

const char *if_name = "tap0";

#define const_htons(x) (((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8))

#define ETH_MTU 1536


#define ARRAY_LEN(array) (sizeof(array) / sizeof(*(array)))


bool mac_eq(struct mac_address a, struct mac_address b) {
    return memcmp(&a, &b, 6);
}

const struct mac_address broadcast_mac = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
const struct mac_address zero_mac = {{0, 0, 0, 0, 0, 0}};


typedef uint32_t be32;
typedef uint16_t be16;


struct sock {
};
struct udp_sock {
    struct sock sock;
    int ip_id;
    be32 source_ip;
    be32 destination_ip;
    be32 source_port;
    be32 destination_port;
};


struct route {
    be32 prefix;
    be32 netmask;
    be32 next_hop;
};

struct route route_table[1];

be32 best_route(be32 address) {
    int best_prefix = -1;
    int best_next_hop = 0;
    for (int i=0; i<ARRAY_LEN(route_table); i++) {
        if ((address & route_table[i].netmask) == route_table[i].prefix) {
            if (route_table[i].prefix > best_prefix) {
                best_next_hop = route_table[i].next_hop;
                best_prefix = route_table[i].prefix;
            }
        }
    }

    return best_next_hop;
}

struct pkb;

struct arp_cache_line {
    be32 ip;
    struct mac_address mac;
};

struct arp_cache {
#define ARP_CACHE_LEN 32
    struct arp_cache_line cl[ARP_CACHE_LEN];
};


struct net_if {
    struct mac_address mac_address;
    be32 ip;
    be32 netmask;

#if __linux__
    int fd;
#elif __ngk__
    struct net_if *intf;
#endif

    struct arp_cache arp_cache;
    struct list pending_mac_queries;

    size_t (*write_to_wire)(struct net_if *, struct pkb *);
};

struct pkb {
    uint8_t anno[32];
    struct net_if *from;
    long length; // -1 if unknown

    char buffer[];
};

struct pkb *new_pkb() {
    struct pkb *new_pk = calloc(1, sizeof(struct pkb) + ETH_MTU);
    new_pk->length = -1;
    new_pk->from = NULL;
    return new_pk;
}

void free_pkb(struct pkb *pkb) {
    free(pkb);
}


struct ethernet_header;
struct arp_header;
struct ip4_header;
struct icmp_header;
struct udp_header;

struct tcp_socket;
struct udp_socket;
struct icmp_socket; // ?
struct ip_socket; // raw sockets?


struct ethernet_header *ethernet(struct pkb *pk) {
    return (struct ethernet_header *)&pk->buffer;
}

struct arp_header *arp(struct pkb *pk) {
    return (struct arp_header *)&pk->buffer + sizeof(struct ethernet_header);
}

struct ip4_header *ip4(struct pkb *pk) {
    return (struct ip4_header *)&pk->buffer + sizeof(struct ethernet_header);
}

struct udp_header *udp(struct ip4_header *ip4) {
    return (struct udp_header *)((char *)ip4 + (ip4->header_length * 32));
}

struct icmp_header *icmp(struct ip4_header *ip4) {
    return (struct icmp_header *)((char *)ip4 + (ip4->header_length * 32));
}

long ip_len(struct pkb *pk) {
    struct ethernet_header *eth = ethernet(pk);
    if (eth->ethertype != htons(ETH_IP)) {
        return 0;
    }

    struct ip4_header *ip = ip4(pk);
    return ip->total_length + sizeof(struct ethernet_header);
}


// below
void reply_icmp(struct pkb *resp, struct pkb *pk);

// below
void ip_checksum(struct pkb *);
void icmp_checksum(struct pkb *);

// TODO
void udp_checksum(struct pkb *);

// below
void dispatch(struct pkb *);

void echo_icmp(struct pkb *pk) {
    struct pkb *resp = new_pkb();
    reply_icmp(resp, pk);
    dispatch(resp);
    free_pkb(resp);
}

void reply_icmp(struct pkb *resp, struct pkb *pk) {
    struct ethernet_header *r_eth = ethernet(resp);
    r_eth->ethertype = htons(ETH_ARP);

    struct ip4_header *r_ip4 = ip4(resp);
    struct ip4_header *s_ip4 = ip4(pk);

    r_ip4->version = 4;
    r_ip4->header_length = 5;
    r_ip4->dscp = 0;
    r_ip4->total_length = 0;
    r_ip4->id = s_ip4->id;
    r_ip4->flags_frag = htons(0x4000); // DNF - make this better
    r_ip4->ttl = 64;
    r_ip4->proto = IPPROTO_ICMP;
    r_ip4->source_ip = s_ip4->destination_ip;
    r_ip4->destination_ip = s_ip4->source_ip;

    struct icmp_header *r_icmp = icmp(r_ip4);
    struct icmp_header *s_icmp = icmp(s_ip4);

    size_t icmp_data_len = htons(s_ip4->total_length) -
                           sizeof(struct ip4_header) - 
                           sizeof(struct icmp_header);

    r_icmp->type = ICMP_ECHO_RESP;
    r_icmp->code = 0;
    r_icmp->checksum = 0;
    r_icmp->ident = s_icmp->ident;
    r_icmp->sequence = s_icmp->sequence;
    r_icmp->timestamp = s_icmp->timestamp;
    r_icmp->timestamp_low = s_icmp->timestamp_low;

    memcpy(r_icmp->data, s_icmp->data, icmp_data_len);

    ip_checksum(resp);
    icmp_checksum(resp);

    resp->length = ip_len(resp);
}

void make_udp(struct udp_sock *sock, struct pkb *pk, void *data, size_t len) {
    struct ethernet_header *r_eth = ethernet(pk);
    r_eth->ethertype = htons(ETH_ARP);

    struct ip4_header *r_ip4 = ip4(pk);

    r_ip4->version = 4;
    r_ip4->header_length = 5;
    r_ip4->dscp = 0;
    r_ip4->total_length = sizeof(struct ip4_header) + sizeof(struct udp_header) + len;
    r_ip4->id = sock->ip_id;
    r_ip4->flags_frag = htons(0x4000); // DNF - make this better
    r_ip4->ttl = 64;
    r_ip4->proto = IPPROTO_ICMP;
    r_ip4->source_ip = sock->source_ip;
    r_ip4->destination_ip = sock->destination_ip;

    struct udp_header *r_udp = udp(r_ip4);

    r_udp->source_port = sock->source_port;
    r_udp->destination_port = sock->destination_port;
    r_udp->length = len;
    r_udp->checksum = 0;

    memcpy(r_udp->data, data, len);

    ip_checksum(pk);
    udp_checksum(pk);
}

// below
void query_for(struct net_if *intf, be32 address, struct pkb *pk);
struct mac_address arp_cache_get(struct net_if *intf, be32 ip);

// TODO
struct net_if *interface_containing(be32 ip);

void dispatch(struct pkb *pk) {
    struct ip4_header *ip = ip4(pk);
    be32 next_hop = best_route(ip->destination_ip);

    struct net_if *intf = interface_containing(next_hop);
    if (next_hop == intf->ip) {
        // it was me all along!
    }

    struct mac_address d;
    d = arp_cache_get(intf, next_hop);

    if (!mac_eq(d, zero_mac)) {
        struct ethernet_header *eth = ethernet(pk);
        eth->source_mac = intf->mac_address;
        eth->destination_mac = d;

        intf->write_to_wire(intf, pk);
    } else {
        query_for(intf, next_hop, pk);
    }
}

struct pending_mac_query {
    be32 ip;
    struct mac_address mac;

    int attempts;

    struct list pending_pks;
};


void arp_cache_put(struct net_if *intf, be32 ip, struct mac_address mac) {
    struct arp_cache *ac = &intf->arp_cache;

    for (int i=0; i<ARP_CACHE_LEN; i++) {
        if (ac->cl[i].ip == 0) {
            ac->cl[i].ip = ip;
            ac->cl[i].mac = mac;
        }
    }

    struct list_n *node = intf->pending_mac_queries.head;
    while (node) {
        struct pending_mac_query *q = node->v;

        if (q->ip == ip) {
            // TODO
            // allow the packets out with the new MAC as destination
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

// below
void arp_query(struct pkb *pk, be32 address, struct net_if *intf);

void query_for(struct net_if *intf, be32 address, struct pkb *pk) {
    struct list_n *node = intf->pending_mac_queries.head;

    while (node) {
        struct pending_mac_query *q = node->v;
        if (address == q->ip) {
            if (pk) {
                list_append(&q->pending_pks, pk);
            }
            return;
        }
        node = node->next;
    }

    // The query has not been sent

    struct pending_mac_query *q = malloc(sizeof(*q));

    q->ip = address;
    q->mac = zero_mac;
    q->attempts = 1;
    q->pending_pks.head = NULL;
    q->pending_pks.tail = NULL;

    list_append(&q->pending_pks, pk);
    list_append(&intf->pending_mac_queries, q);

    struct pkb *arp = new_pkb();
    arp_query(arp, address, intf);
    intf->write_to_wire(intf, arp);
}


void arp_query(struct pkb *pk, be32 address, struct net_if *intf) {
    struct ethernet_header *eth = ethernet(pk);
    eth->destination_mac = broadcast_mac;
    eth->source_mac = intf->mac_address;
    eth->ethertype = htons(ETH_ARP);

    struct arp_header *r_arp = arp(pk);
    r_arp->hw_type = htons(1);      // ethernet
    r_arp->proto = htons(0x0800);   // ip4
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

void print_ip_addr(uint32_t ip) {
    printf("%i.%i.%i.%i",
            (ip >> 24) & 0xff, (ip >> 16) & 0xff,
            (ip >> 8) & 0xff, ip & 0xff);
}

void print_arp_pkt(struct pkb *pk) {
    struct arp_header *a = arp(pk);

    int op = ntohs(a->op);
    if (op == ARP_REQ) {
        printf("ARP Request who-has ");
        print_ip_addr(ntohl(a->target_ip));
        printf(" tell ");
        print_ip_addr(ntohl(a->sender_ip));
        printf("\n");
    } else if (op == ARP_RESP) {
        printf("ARP Responce ");
        print_ip_addr(ntohl(a->sender_ip));
        printf(" is-at ");
        print_mac_address(a->sender_mac);
        printf("\n");
    } else {
        printf("Unrecognised ARP OP: %i\n", ntohs(a->op));
    }
}

void ip_checksum(struct pkb *pk) {
    struct ip4_header *ip = ip4(pk);

    uint16_t *ip_chunks = (uint16_t *)ip;
    uint32_t checksum32 = 0;
    for (int i=0; i<ip->header_length*2; i+=1) {
        checksum32 += ip_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    ip->header_checksum = ~checksum;
}

void udp_checksum(struct pkb *pk) {
    struct ip4_header *ip = ip4(pk);
    struct udp_header *u = udp(ip);

    // TODO actually calculate UDP checksums
    u->checksum = 0;
}

/*
struct tcp_pseudoheader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t _zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

void place_tcp_checksum(struct ip_hdr *ip) {
    struct tcp_pkt *tcp = (void *)(ip + 1);

    int length = ntohs(ip->total_length);

    struct tcp_pseudoheader t = {
        ip->src_ip,
        ip->dst_ip,
        0,
        PROTO_TCP,
        htons(length - sizeof(struct ip_hdr)),
    };

    uint32_t sum = 0;
    uint16_t *c = (uint16_t *)&t;
    for (int i=0; i<sizeof(t)/2; i++) {
        sum += c[i];
    }

    int n_bytes = length - sizeof(struct ip_hdr);
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
*/

void icmp_checksum(struct pkb *pk) {
    struct ip4_header *r_ip4 = ip4(pk);
    struct icmp_header *r_icmp = icmp(r_ip4);

    size_t extra_len = r_ip4->total_length -
                        sizeof(struct ip4_header) -
                        sizeof(struct icmp_header);

    uint16_t *icmp_chunks = (uint16_t *)r_icmp;
    uint32_t checksum32 = 0;
    for (int i=0; i<(sizeof(struct icmp_header) + extra_len)/2; i+=1) {
        checksum32 += icmp_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    r_icmp->checksum = ~checksum;
}

size_t linux_write_to_wire(struct net_if *intf, struct pkb *pk) {
    int fd = intf->fd;
    long len;
    void *buf = pk->buffer;

    struct ip4_header *ip;

    if (pk->length > 0) {
        len = pk->length;
    } else if ((ip = ip4(pk))) {
        len = ip->total_length + sizeof(struct ethernet_header);
    } else {
        printf("length unknown for pkb!\n");
        return -1;
    }

    printf("Sending this:\n");
    for (int i=0; i<len; i++) {
        printf("%02hhx ", ((uint8_t *)buf)[i]);
    }
    printf("\n");

    size_t written_len = write(fd, buf, len);

    printf("Wrote %li (%s)\n", len, strerror(errno));
    return written_len;
}

void arp_reply(struct pkb *resp, struct pkb *pk) {
    struct ethernet_header *r_eth = ethernet(resp);
    struct arp_header *s_arp = arp(pk);
    struct arp_header *r_arp = arp(resp);

    r_eth->source_mac = pk->from->mac_address;
    r_eth->destination_mac = broadcast_mac;
    r_eth->ethertype = htons(ETH_ARP);

    r_arp->hw_type = htons(1);      // ethernet
    r_arp->proto = htons(0x0800);   // ip4
    r_arp->hw_size = 6;
    r_arp->proto_size = 4;
    r_arp->op = htons(ARP_REQ);
    r_arp->sender_mac = pk->from->mac_address;
    r_arp->sender_ip = pk->from->ip;
    r_arp->target_mac = s_arp->sender_mac;
    r_arp->target_ip = s_arp->sender_ip;

    resp->length = sizeof(struct ethernet_header) +
                   sizeof(struct arp_header);
}

void process_arp_packet(struct pkb *pk) {
    print_arp_pkt(pk);
    struct arp_header *a = arp(pk);
    arp_cache_put(pk->from, a->sender_ip, a->sender_mac);

    if (a->op == htons(ARP_REQ) && a->target_ip == pk->from->ip) {
        struct pkb *resp = new_pkb();
        arp_reply(resp, pk);
        pk->from->write_to_wire(pk->from, resp);
        free_pkb(resp);
    }
}

void process_ip_packet(struct pkb *pk) {
    struct ip4_header *ip = ip4(pk);

    printf("IP detected, next type %#02hhx\n", ip->proto);
    if (ip->destination_ip != pk->from->ip) {
        printf("Not for my IP, ignoring\n");
        return;
    }
    
    switch (ip->proto) {
    case PROTO_ICMP:
        echo_icmp(pk);
        break;
    case PROTO_UDP:
        // socket_dispatch_udp(pk);
        break;
    case PROTO_TCP:
        // socket_dispatch_tcp(pk);
        break;
    default:
        printf("Unknown IP protocol %i\n", ip->proto);
        break;
    }
}

void process_ethernet(struct pkb *pk) {
    struct ethernet_header *eth = ethernet(pk);
    struct mac_address dst_mac = eth->destination_mac;
    struct mac_address my_mac = pk->from->mac_address;

    if (mac_eq(dst_mac, my_mac) != 0 && mac_eq(dst_mac, broadcast_mac) != 0) {
        printf("Not for my MAC addr, ignoring\n");
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
        printf("Unknown ethertype %#06hx\n", ntohs(eth->ethertype));
        break;
    }
}

struct net_if interfaces[] = {
    {
        .mac_address = {{0x02, 0x00, 0x00, 0x12, 0x34, 0x56}},
        .ip = 0xac1f0102,
        .netmask = 0xffffff00,
        .fd = -1,
        .arp_cache = {},
        .pending_mac_queries = {0},
        .write_to_wire = linux_write_to_wire,
    },
};

struct net_if *interface_containing(be32 ip) {
    if (ip == interfaces[0].ip) {
        return &interfaces[0];
    } else {
        return NULL;
    }
}

struct route route_table[] = {
    {0x00000000, 0x00000000, 0xac1f0101}, // 172.31.1.1
};

int main() {
    init_global_lists();

    int fd = tun_alloc(if_name);
    if (fd < 0) {
        perror("tun_alloc");
    }

    interfaces[0].fd = fd;

    while (true) {
        struct pkb *pk = new_pkb();

        int count = read(fd, pk->buffer, ETH_MTU);
        if (count <= 0) {
            perror("read interface");
        }

        pk->from = &interfaces[0];
        pk->length = count;

        process_ethernet(pk);

        free_pkb(pk);
    }

}

