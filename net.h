
#ifndef IPSTACK_NET_H
#define IPSTACK_NET_H 1

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/if.h>

#ifdef __GNUC__
# define _packed __attribute__((packed))
#else
# error "Need to support non-GNUC first to ensure struct packing"
#endif

struct _packed mac_addr {
    char data[6];
};

enum ethertype {
    ETH_IP = 0x0800,
    ETH_ARP = 0x0806,
};

struct _packed eth_hdr {
    struct mac_addr dst_mac;
    struct mac_addr src_mac;
    uint16_t ethertype;
    uint8_t data[0];
};

struct _packed arp_pkt {
    // eth_hdr
    uint16_t hw_type;
    uint16_t proto;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t op;
    struct mac_addr sender_mac;
    uint32_t sender_ip;
    struct mac_addr target_mac;
    uint32_t target_ip;
};

enum ip_protocol_numbers {
    PROTO_ICMP = 1,
    PROTO_TCP = 6,  // IPPROTO_TCP
    PROTO_UDP = 17, // IPPROTO_UDP
};

struct _packed ip_hdr {
    // eth_hdr
    uint8_t hdr_len : 4;
    uint8_t version : 4;
    uint8_t dscp;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t hdr_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t data[0];
};

enum icmp_type {
    ICMP_ECHO_REQ = 8,
    ICMP_ECHO_RESP = 0,
};

struct _packed icmp_pkt {
    // ip_hdr
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t ident;
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t timestamp_low;
    uint8_t data[0];
};

struct _packed udp_pkt {
    // ip_hdr
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
    uint8_t data[0];
};

struct _packed tcp_pkt {
    // ip hdr
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t f_fin : 1;
    uint16_t f_syn : 1;
    uint16_t f_rst : 1;
    uint16_t f_psh : 1;
    uint16_t f_ack : 1;
    uint16_t f_urg : 1;
    uint16_t _reserved : 6;
    uint16_t offset : 4;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

enum arp_op {
    ARP_REQ = 1,
    ARP_RESP = 2,
};

struct mac_addr resolve_mac(int fd, uint32_t ip);
size_t make_eth_hdr(struct eth_hdr *pkt, struct mac_addr, uint16_t ethertype);
size_t make_ip_hdr(struct ip_hdr *, uint16_t id, uint8_t proto, uint32_t dst);
void place_ip_checksum(struct ip_hdr *);
void place_tcp_checksum(struct ip_hdr *);
size_t write_to_wire(int fd, const void *, size_t);
int route(uint32_t ip);

#endif // IPSTACK_NET_H

