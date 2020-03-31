
#ifndef IPSTACK_NET_H
#define IPSTACK_NET_H 1

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "list.h"

#ifdef __GNUC__
# define _packed __attribute__((packed))
#else
# error "Need to support non-GNUC first to ensure struct packing"
#endif

struct socket_impl;

#define const_htons(x) (((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8))
#define ETH_MTU 1536
#define ARRAY_LEN(array) (sizeof(array) / sizeof(*(array)))

struct socket_impl;

typedef uint32_t be32;
typedef uint16_t be16;

struct _packed mac_address {
    char data[6];
};

enum ethertype {
    ETH_IP = 0x0800,
    ETH_ARP = 0x0806,
};

struct _packed ethernet_header {
    struct mac_address destination_mac;
    struct mac_address source_mac;
    be16 ethertype;
    char data[];
};

struct _packed arp_header {
    // eth_hdr
    be16 hw_type;
    be16 proto;
    uint8_t hw_size;
    uint8_t proto_size;
    be16 op;
    struct mac_address sender_mac;
    be32 sender_ip;
    struct mac_address target_mac;
    be32 target_ip;
};

enum ip_protocol_numbers {
    PROTO_ICMP = 1,
    PROTO_TCP = 6,  // IPPROTO_TCP
    PROTO_UDP = 17, // IPPROTO_UDP
};

struct _packed ip_header {
    // eth_hdr
    uint8_t header_length : 4;
    uint8_t version : 4;
    uint8_t dscp;
    be16 total_length;
    be16 id;
    be16 flags_frag;
    uint8_t ttl;
    uint8_t proto;
    be16 header_checksum;
    be32 source_ip;
    be32 destination_ip;
    char data[];
};

enum icmp_type {
    ICMP_ECHO_REQ = 8,
    ICMP_ECHO_RESP = 0,
};

struct _packed icmp_header {
    // ip_hdr
    uint8_t type;
    uint8_t code;
    be16 checksum;
    be16 ident;
    be16 sequence;
    be32 timestamp;
    be32 timestamp_low;
    char data[];
};

struct _packed udp_header {
    // ip_hdr
    be16 source_port;
    be16 destination_port;
    be16 length;
    be16 checksum;
    char data[];
};

enum tcp_flags {
    TCP_NONE = 0,
    TCP_URG = 1 << 0,
    TCP_ACK = 1 << 1,
    TCP_PSH = 1 << 2,
    TCP_RST = 1 << 3,
    TCP_SYN = 1 << 4,
    TCP_FIN = 1 << 5,
};

struct _packed tcp_header {
    // ip hdr
    be16 source_port;
    be16 destination_port;
    be32 seq;
    be32 ack;
    be16 _reserved : 4;
    be16 offset : 4;
    be16 f_fin : 1;
    be16 f_syn : 1;
    be16 f_rst : 1;
    be16 f_psh : 1;
    be16 f_ack : 1;
    be16 f_urg : 1;
    be16 _reserved2 : 2;
    be16 window;
    be16 checksum;
    be16 urg_ptr;
    char data[];
};

typedef struct mac_address mac_address;

enum arp_op {
    ARP_REQ = 1,
    ARP_RESP = 2,
};

static const struct mac_address broadcast_mac = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
static const struct mac_address zero_mac = {{0, 0, 0, 0, 0, 0}};

struct pkb {
    uint8_t anno[32];
    struct net_if *from;
    long length; // -1 if unknown

    char buffer[];
};

struct route {
    be32 prefix;
    be32 netmask;
    be32 next_hop;
};

struct arp_cache_line {
    be32 ip;
    struct mac_address mac;
};

struct arp_cache {
#define ARP_CACHE_LEN 32
    struct arp_cache_line cl[ARP_CACHE_LEN];
};

struct pending_mac_query {
    be32 ip;
    struct mac_address mac;

    int attempts;

    struct list pending_pks;
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

extern struct net_if interfaces[1];
extern struct route route_table[1];

int tun_alloc(const char *tun_name);

struct pkb *new_pk();
struct pkb *new_pk_len(size_t len);
void free_pk(struct pkb *pkb);

struct mac_address mac_from_str_trad(char *mac_str);
struct mac_address mac_from_str(char *mac_str);
void print_mac_address(struct mac_address mac);
bool mac_eq(struct mac_address a, struct mac_address b);

uint32_t ip_from_str(char *ip_str);
void print_ip_addr(uint32_t ip);
void print_arp_pkt(struct pkb *pk);

struct ethernet_header *eth_hdr(struct pkb *pk);
struct arp_header *arp_hdr(struct pkb *pk);
struct ip_header *ip_hdr(struct pkb *pk);
struct udp_header *udp_hdr(struct ip_header *ip);
struct tcp_header *tcp_hdr(struct ip_header *ip);
struct icmp_header *icmp_hdr(struct ip_header *ip);

long ip_len(struct pkb *pk);

void ip_checksum(struct pkb *);
void icmp_checksum(struct pkb *);
void udp_checksum(struct pkb *);
void tcp_checksum(struct pkb *ip);

void process_ethernet(struct pkb *pk);

void query_for(struct net_if *intf, be32 address, struct pkb *pk);
void arp_query(struct pkb *pk, be32 address, struct net_if *intf);
struct mac_address arp_cache_get(struct net_if *intf, be32 ip);
void arp_cache_put(struct net_if *intf, be32 ip, struct mac_address mac);
void arp_reply(struct pkb *resp, struct pkb *pk);
void process_arp_packet(struct pkb *pk);

void process_ip_packet(struct pkb *pk);

void echo_icmp(struct pkb *pk);
void reply_icmp(struct pkb *resp, struct pkb *pk);

void make_udp(struct socket_impl *s, struct pkb *pk,
        struct sockaddr_in *d_addr, const void *data, size_t len);
void make_tcp(struct socket_impl *s, struct pkb *pk,
        int flags, const void *data, size_t len);

void dispatch(struct pkb *pk);
be32 best_route(be32 address);
struct net_if *interface_containing(be32 ip);
size_t linux_write_to_wire(struct net_if *intf, struct pkb *pk);

#endif // IPSTACK_NET_H

