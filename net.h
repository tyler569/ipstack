
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
    uint16_t ethertype;
    uint8_t data[0];
};

struct _packed arp_header {
    // eth_hdr
    uint16_t hw_type;
    uint16_t proto;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t op;
    struct mac_address sender_mac;
    uint32_t sender_ip;
    struct mac_address target_mac;
    uint32_t target_ip;
};

enum ip_protocol_numbers {
    PROTO_ICMP = 1,
    PROTO_TCP = 6,  // IPPROTO_TCP
    PROTO_UDP = 17, // IPPROTO_UDP
};

struct _packed ip4_header {
    // eth_hdr
    uint8_t header_length : 4;
    uint8_t version : 4;
    uint8_t dscp;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t data[0];
};

enum icmp_type {
    ICMP_ECHO_REQ = 8,
    ICMP_ECHO_RESP = 0,
};

struct _packed icmp_header {
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

struct _packed udp_header {
    // ip_hdr
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t data[0];
};

struct _packed tcp_header {
    // ip hdr
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t _reserved : 4;
    uint16_t offset : 4;
    uint16_t f_fin : 1;
    uint16_t f_syn : 1;
    uint16_t f_rst : 1;
    uint16_t f_psh : 1;
    uint16_t f_ack : 1;
    uint16_t f_urg : 1;
    uint16_t _reserved2 : 2;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

typedef struct mac_address mac_address;

enum arp_op {
    ARP_REQ = 1,
    ARP_RESP = 2,
};

// TODO:
// functions

#endif // IPSTACK_NET_H

