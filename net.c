
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
// #include <net/if_tun.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include "net.h"
#include "socket.h"

const char *if_name = "tap0";

#define const_htons(x) (((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8))

#define ETH_MTU 1536

bool mac_eq(struct mac_addr a, struct mac_addr b) {
    return memcmp(&a, &b, 6);
}

// Defined in main();
struct mac_addr my_mac;

struct mac_addr bcast_mac;
struct mac_addr zero_mac;

uint32_t my_ip;

// "arp table"
uint32_t gateway_ip;
struct mac_addr gateway_mac;

// "route table"
int nic_fd;

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

struct mac_addr mac_from_str_trad(char *mac_str) {
    struct mac_addr res = {0};
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

struct mac_addr mac_from_str(char *mac_str) {
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

void print_mac_addr(struct mac_addr mac) {
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

size_t make_eth_hdr(struct eth_hdr *pkt, struct mac_addr dst, uint16_t type) {
    pkt->dst_mac = dst;
    pkt->src_mac = my_mac;
    pkt->ethertype = htons(type);
    return sizeof(struct eth_hdr);
}

size_t make_ip_arp_req(void *buf, char *my_ip, char *req_ip) {
    struct eth_hdr *req = buf;
    size_t loc = make_eth_hdr(req, bcast_mac, 0x0806);

    struct arp_pkt *arp = (void *)&req->data;
    arp->hw_type = htons(1); // Ethernet
    arp->proto = htons(0x0800); // IP
    arp->hw_size = 6;
    arp->proto_size = 4;
    arp->op = htons(ARP_REQ);
    arp->sender_mac = my_mac; // global - consider parametrizing this
    arp->sender_ip = htonl(ip_from_str(my_ip));
    arp->target_mac = zero_mac;
    arp->target_ip = htonl(ip_from_str(req_ip));

    return loc + sizeof(*arp);
}

size_t make_ip_arp_resp(void *buf, struct arp_pkt *req) {
    struct eth_hdr *resp = buf;

    size_t loc = make_eth_hdr(resp, req->sender_mac, 0x0806);

    struct arp_pkt *arp = (void *)&resp->data;
    arp->hw_type = htons(1); // Ethernet
    arp->proto = htons(0x0800); // IP
    arp->hw_size = 6;
    arp->proto_size = 4;
    arp->op = htons(ARP_RESP);
    arp->sender_mac = my_mac; // global - consider parametrizing this
    arp->sender_ip = my_ip;
    arp->target_mac = req->sender_mac;
    arp->target_ip = req->sender_ip;

    return loc + sizeof(*arp);
}


void print_arp_pkt(struct arp_pkt *arp) {
    int op = ntohs(arp->op);
    if (op == ARP_REQ) {
        printf("ARP Request who-has ");
        print_ip_addr(ntohl(arp->target_ip));
        printf(" tell ");
        print_ip_addr(ntohl(arp->sender_ip));
        printf("\n");
    } else if (op == ARP_RESP) {
        printf("ARP Responce ");
        print_ip_addr(ntohl(arp->sender_ip));
        printf(" is-at ");
        print_mac_addr(arp->sender_mac);
        printf("\n");
    } else {
        printf("Unrecognised ARP OP: %i\n", ntohs(arp->op));
    }
}

void place_ip_checksum(struct ip_hdr *ip) {
    uint16_t *ip_chunks = (uint16_t *)ip;
    uint32_t checksum32 = 0;
    for (int i=0; i<ip->hdr_len*2; i+=1) {
        checksum32 += ip_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    ip->hdr_checksum = ~checksum;
}

size_t make_ip_hdr(struct ip_hdr *ip, uint16_t id, uint8_t proto, uint32_t dst_ip) {
    ip->version = 4;
    ip->hdr_len = 5;
    ip->dscp = 0;
    ip->total_len = 0; // get later!
    ip->id = id;
    /*
    ip->reserved = 0;
    ip->dnf = 1;
    ip->_reserved0 = 0;
    ip->frag_off = 0;
    */
    ip->flags_frag = htons(0x4000); // dnf
    ip->ttl = 255;
    ip->proto = proto;
    ip->hdr_checksum = 0; // get later!
    ip->src_ip = my_ip;
    ip->dst_ip = dst_ip;

    return sizeof(*ip);
};

void place_icmp_checksum(struct icmp_pkt *icmp, size_t extra_len) {
    uint16_t *icmp_chunks = (uint16_t *)icmp;
    uint32_t checksum32 = 0;
    for (int i=0; i<(sizeof(struct icmp_pkt) + extra_len)/2; i+=1) {
        checksum32 += icmp_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    icmp->checksum = ~checksum;
}

size_t make_icmp_resp(void *buf, struct icmp_pkt *req, size_t len) {
    struct icmp_pkt *icmp = buf;
    
    icmp->type = ICMP_ECHO_RESP;
    icmp->code = 0;
    icmp->checksum = 0; // get later!
    icmp->ident = req->ident; // stays in network byte-order
    icmp->sequence = req->sequence; // stays in network byte-order
    icmp->timestamp = req->timestamp; // stays in network byte-order
    icmp->timestamp_low = req->timestamp_low; // stays in network byte-order

    memcpy(&icmp->data, &req->data, len);
    
    return sizeof(*icmp) + len;
}

size_t make_udp_resp(void *buf, struct udp_pkt *req, size_t len) {
    struct udp_pkt *udp = buf;

    udp->src_port = req->dst_port;
    udp->dst_port = req->src_port;
    udp->len = req->len;
    udp->checksum = 0; // checksum disabled;

    memcpy(&udp->data, &req->data, len);

    return sizeof(*udp) + len;
}

size_t write_to_wire(int fd, const void *buf, size_t len) {
    printf("Sending this:\n");
    for (int i=0; i<len; i++) {
        printf("%02hhx ", ((uint8_t *)buf)[i]);
    }
    printf("\n");

    size_t written_len = write(fd, buf, len);

    printf("Wrote %li (%s)\n", len, strerror(errno));
    return written_len;
}

void place_arp_entry(uint32_t ip, struct mac_addr mac) {
    // TODO: Real ARP cache
    if (ip == gateway_ip) {
        gateway_mac = mac;
    }
}

struct mac_addr resolve_mac(int fd, uint32_t ip) {
    if (ip == gateway_ip) { // ip in arp_cache
        return gateway_mac;
    }
    
    void *buf = malloc(ETH_MTU);
    // send arp request
    size_t len = make_ip_arp_req(buf, "10.50.1.2", "10.50.1.1");
    write_to_wire(fd, buf, len);
    free(buf);

    return zero_mac;
    // packets that receive this should wait for an ARP responce
}
    
void process_arp_packet(int fd, void *buf) {
    struct eth_hdr *eth = buf;
    struct arp_pkt *arp = buf + sizeof(*eth);

    print_arp_pkt(arp);

    place_arp_entry(arp->sender_ip, arp->sender_mac);

    if (arp->op == htons(ARP_REQ)) {
        void *resp = malloc(ETH_MTU);
        // make_eth_hdr
        size_t len = make_ip_arp_resp(resp, arp);
        write_to_wire(fd, resp, len);
        free(resp);
    }

    // TODO
    // check to see if any packets are waiting on this IP's mac
    // send them.
}

void echo_icmp(int fd, void *buf) {
    struct eth_hdr *eth = buf;
    struct ip_hdr *ip = buf + sizeof(*eth);
    struct icmp_pkt *icmp = (void *)ip + sizeof(*ip);

    struct mac_addr dest_mac = resolve_mac(fd, ip->src_ip);

    printf("ICMP detected, type %i\n", icmp->type);
    if (icmp->type != ICMP_ECHO_REQ) {
        printf("Not an echo request, ignoring\n");
        return;
    }

    void *sendbuf = malloc(ETH_MTU);
    size_t index = make_eth_hdr(sendbuf, dest_mac, ETH_IP);
    struct ip_hdr *hdr = sendbuf + index;
    index += make_ip_hdr(hdr, ip->id, PROTO_ICMP, ip->src_ip);
    struct icmp_pkt *pkt = sendbuf + index;
    size_t icmp_data_len = ntohs(ip->total_len) - sizeof(*hdr) - sizeof(*pkt);
    printf("total icmp data length: %li\n", icmp_data_len);
    index += make_icmp_resp(pkt, icmp, icmp_data_len);
    hdr->ttl = ip->ttl;

    hdr->total_len = htons(index - sizeof(struct eth_hdr));
    place_ip_checksum(hdr);
    place_icmp_checksum(pkt, icmp_data_len);
    write_to_wire(fd, sendbuf, index);
    free(sendbuf);
}

/*
void echo_udp(int fd, void *buf) {
    struct eth_hdr *eth = buf;
    struct ip_hdr *ip = buf + sizeof(*eth);
    struct udp_pkt *udp = (void *)ip + sizeof(*ip);

    struct mac_addr dest_mac = resolve_mac(fd, ip->src_ip);

    void *sendbuf = malloc(ETH_MTU);
    size_t index = make_eth_hdr(sendbuf, dest_mac, my_mac, ETH_IP);
    struct ip_hdr *sendip = sendbuf + index;
    index += make_ip_hdr(sendip, ntohs(ip->id), PROTO_UDP, ip->src_ip);
    struct udp_pkt *sendudp = sendbuf + index;
    index += make_udp_resp(sendudp, udp, ntohs(ip->total_len) - sizeof(*sendip) - sizeof(*sendudp));

    sendip->total_len = htons(index - sizeof(struct eth_hdr));
    place_ip_checksum(sendip);
    write_to_wire(fd, sendbuf, index);
    free(sendbuf);
}
*/

void process_ip_packet(int fd, void *buf) {
    struct eth_hdr *eth = buf;
    struct ip_hdr *ip = buf + sizeof(*eth);

    printf("IP detected, next type %#02hhx\n", ip->proto);
    if (ip->dst_ip != my_ip) {
        printf("Not for my IP, ignoring\n");
        return;
    }
    
    switch (ip->proto) {
    case PROTO_ICMP:
        echo_icmp(fd, buf);
        break;
    case PROTO_UDP:
        socket_dispatch_udp(eth);
        break;
    default:
        printf("Unknown IP protocol %i\n", ip->proto);
        break;
    }
}

void process_ethernet(int fd, void *buf) {
    struct eth_hdr *eth = buf;
    struct mac_addr dst_mac = eth->dst_mac;

    if (mac_eq(dst_mac, my_mac) != 0 && mac_eq(dst_mac, bcast_mac) != 0) {
        printf("Not for my MAC addr, ignoring\n");
        return;
    }

    switch (eth->ethertype) {
    case const_htons(ETH_ARP):
        process_arp_packet(fd, buf);
        break;
    case const_htons(ETH_IP):
        process_ip_packet(fd, buf);
        break;
    default:
        printf("Unknown ethertype %#06hx\n", htons(eth->ethertype));
        break;
    }
}

int route(uint32_t dst_ip) {
    // TODO real routing decisions
    // TODO loopback
    return nic_fd;
}

void *udp_echo(void *data);

int main() {
    // Global initializations - declared above 
    my_mac = mac_from_str("0e:11:22:33:44:55"); // hardcode

    my_ip = htonl(ip_from_str("10.50.1.2"));  // get from DHCP

    bcast_mac = mac_from_str("ff:ff:ff:ff:ff:ff");  // make into constant
    zero_mac = mac_from_str("00:00:00:00:00:00");   // make into constant

    gateway_ip = htonl(ip_from_str("10.50.1.1"));  // get from DHCP

    int fd = tun_alloc(if_name);
    nic_fd = fd;
    printf("Got a file descriptor (or something)! - %i\n", fd);

    if (fd > 0) {
        printf("It's probably real too, let's try it!\n");
    } else {
        printf("Imma guess it's not good though, and die here\n");
        printf("Did you make that tun adapter and set it up?\n");
        exit(0);
    }

    struct eth_hdr *req = malloc(ETH_MTU);
    size_t len = make_ip_arp_req(req, "10.50.1.2", "10.50.1.1");
    write_to_wire(fd, req, len);
    free(req);

    pthread_t udp_echo_th;

    int *port = malloc(sizeof(int));
    *port = 1099;
    pthread_create(&udp_echo_th, NULL, udp_echo, port);

    char buf[4096];
    while (true) {
        errno = 0;
        int count = read(fd, buf, 4096);

        if (count <= 0) {
            printf("Error reading interface (%s)\n", strerror(errno));
            exit(0);
        }

        printf("\n");
        printf("Read this from the socket:\n");
        for (int i=0; i<count; i++) {
            printf("%02hhx ", buf[i]);
        }
        printf("\n");

        process_ethernet(fd, buf);

        memset(buf, 0, count);
    }

    void *res;
    pthread_join(udp_echo_th, &res);
    printf("%p\n", res);
}

