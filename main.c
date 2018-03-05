
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

// const char *tun_name = "tap0"

#ifdef __GNUC__
# define __packed __attribute__((packed))
#else
# error "Need to support non-GNUC first to ensure struct packing"
#endif

#define ETH_MTU 1536


struct __packed mac_addr {
    char data[6];
};

uint32_t hash_mac_addr(struct mac_addr mac) {
    uint32_t hash = 0;
    hash += mac.data[5];
    hash += mac.data[4] << 8;
    hash += mac.data[3] << 16;
    hash += mac.data[2];
    hash += mac.data[1] << 8;
    hash += mac.data[0] << 16;

    return hash;
}

struct __packed eth_hdr {
    struct mac_addr dst_mac;
    struct mac_addr src_mac;
    uint16_t type;
    uint8_t data[0];
};

struct __packed arp_pkt {
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

struct __packed ip_hdr {
    // eth_hdr
    uint8_t hdr_len : 4;
    uint8_t version : 4;
    uint8_t dscp;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t hdr_chksm;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t data[0];
};

enum icmp_type {
    ICMP_ECHO_REQ = 8,
    ICMP_ECHO_RESP = 0,
};

struct __packed icmp_pkt {
    // ip_hdr
    uint8_t type;
    uint8_t code;
    uint16_t chksm;
    uint16_t ident;
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t timestamp_low;
    uint8_t data[0];
};

// Defined in main();
struct mac_addr my_mac;
uint32_t my_mac_hash;
struct mac_addr bcast_mac;
uint32_t bcast_mac_hash;
struct mac_addr zero_mac;
uint32_t my_ip;

int tun_alloc(char *tun_name) {
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

size_t make_eth_hdr(struct eth_hdr *pkt, struct mac_addr dst, struct mac_addr src, uint16_t type) {
    pkt->dst_mac = dst;
    pkt->src_mac = src;
    pkt->type = htons(type);
    return sizeof(struct eth_hdr);
}

enum arp_op {
    ARP_REQ = 1,
    ARP_RESP = 2,
};

size_t make_ip_arp_req(void *buf, char *my_ip, char *req_ip) {
    struct eth_hdr *req = buf;
    size_t loc = make_eth_hdr(req, bcast_mac, my_mac, 0x0806);

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

    return loc + sizeof(struct arp_pkt);
}

size_t make_ip_arp_resp(void *buf, struct arp_pkt *req) {
    struct eth_hdr *resp = buf;

    size_t loc = make_eth_hdr(resp, req->sender_mac, my_mac, 0x0806);

    struct arp_pkt *arp = (void *)&resp->data;
    arp->hw_type = htons(1); // Ethernet
    arp->proto = htons(0x0800); // IP
    arp->hw_size = 6;
    arp->proto_size = 4;
    arp->op = htons(ARP_RESP);
    arp->sender_mac = my_mac; // global - consider parametrizing this
    arp->sender_ip = htonl(my_ip);
    arp->target_mac = req->sender_mac;
    arp->target_ip = req->sender_ip;

    return loc + sizeof(struct arp_pkt);
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

void place_ip_chksm(struct ip_hdr *ip) {
    uint16_t *ip_chunks = (uint16_t *)ip;
    uint32_t checksum32 = 0;
    for (int i=0; i<ip->hdr_len*2; i+=1) {
        checksum32 += ip_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    ip->hdr_chksm = ~checksum;
}

size_t make_ip_hdr(void *buf, uint16_t id, uint8_t proto, uint32_t dst_ip) {
    struct ip_hdr *ip = buf;

    ip->version = 4;
    ip->hdr_len = 5;
    ip->dscp = 0;
    ip->total_len = 0; // get later!
    ip->id = htons(id);
    /*
    ip->reserved = 0;
    ip->dnf = 1;
    ip->_reserved0 = 0;
    ip->frag_off = 0;
    */
    ip->flags_frag = htons(0x4000); // dnf
    ip->ttl = 255;
    ip->proto = proto;
    ip->hdr_chksm = 0; // get later!
    ip->src_ip = htonl(my_ip);
    ip->dst_ip = htonl(dst_ip);

    return sizeof(struct ip_hdr);
};

void place_icmp_chksm(struct icmp_pkt *icmp, size_t extra_len) {
    uint16_t *icmp_chunks = (uint16_t *)icmp;
    uint32_t checksum32 = 0;
    for (int i=0; i<(sizeof(struct icmp_pkt) + extra_len)/2; i+=1) {
        checksum32 += icmp_chunks[i];
    }
    uint16_t checksum = (checksum32 & 0xFFFF) + (checksum32 >> 16);

    icmp->chksm = ~checksum;
}

size_t make_icmp_resp(void *buf, struct icmp_pkt *req, size_t len) {
    struct icmp_pkt *icmp = buf;
    
    icmp->type = ICMP_ECHO_RESP;
    icmp->code = 0;
    icmp->chksm = 0; // get later!
    icmp->ident = req->ident; // stays in network byte-order
    icmp->sequence = req->sequence; // stays in network byte-order
    icmp->timestamp = req->timestamp; // stays in network byte-order
    icmp->timestamp_low = req->timestamp_low; // stays in network byte-order

    memcpy(&icmp->data, &req->data, len);
    
    return sizeof(struct icmp_pkt) + len;
}

void write_to_wire(int fd, void *buf, size_t len) {
    printf("Sending this:\n");
    for (int i=0; i<len; i++) {
        printf("%02hhx ", ((uint8_t *)buf)[i]);
    }
    printf("\n");

    errno = 0;
    size_t written_len = write(fd, buf, len);
    if (written_len != len) {
        printf("Actually wrote %i, which is less than requested %i\n",
                written_len, len);
    }

    printf("Wrote %i (%s)\n", len, strerror(errno));
    printf("\n");
}

int main() {
   
    // Global initializations - declared above 
    my_mac = mac_from_str("0e:11:22:33:44:55");
    my_mac_hash = hash_mac_addr(my_mac);
    my_ip = ip_from_str("10.50.1.127");
    bcast_mac = mac_from_str("ff:ff:ff:ff:ff:ff");
    bcast_mac_hash = hash_mac_addr(bcast_mac);
    zero_mac = mac_from_str("00:00:00:00:00:00");

    printf("my mac: %x\n", my_mac_hash);
    printf("bcast mac: %x\n", bcast_mac_hash);

    int fd = tun_alloc("tap0");
    printf("Got a file descriptor (or something)! - %i\n", fd);

    if (fd > 0) {
        printf("It's probably real too, let's try it!\n");
    } else {
        printf("Imma guess it's not good though, and die here\n");
        printf("Did you make that tun adapter and set it up?\n");
        exit(0);
    }

    struct eth_hdr *req = malloc(ETH_MTU);
    size_t len = make_ip_arp_req(req, "10.50.1.127", "10.50.1.1");
    write_to_wire(fd, req, len);
    free(req);

    char buf[4096];
    struct eth_hdr *eth = (void *)buf;
    while (true) {
        int count = read(fd, buf, 4096);

        if (count > 0) {
            uint32_t from = hash_mac_addr(eth->dst_mac);
            if (from != my_mac_hash && from != bcast_mac_hash) {
                printf("Not for me - skipping\n");
                continue;
            }
            printf("Read this from the socket:\n");
            for (int i=0; i<count; i++) {
                printf("%02hhx ", buf[i]);
            }
            printf("\n");

            printf("Ethertype: %#06x\n", ntohs(eth->type));
            if (ntohs(eth->type) == 0x0806) {
                struct arp_pkt *arp = (void *)&eth->data;
                print_arp_pkt(arp);
                if (ntohs(arp->op) == ARP_REQ) {
                    struct eth_hdr *resp = malloc(ETH_MTU);
                    size_t len = make_ip_arp_resp(resp, arp);
                    write_to_wire(fd, resp, len);
                    free(resp);
                }
            } else if (ntohs(eth->type) == 0x0800) {
                struct ip_hdr *ip = (void *)&eth->data;
                printf("IP detected, next type %x\n", ip->proto);
                if (ntohl(ip->dst_ip) != my_ip) {
                    printf("Not for my IP, stopping\n");
                    continue;
                }
                if (ip->proto == 1) {
                    struct icmp_pkt *icmp = (void *)&ip->data;
                    printf("ICMP detected, type %i\n", icmp->type);
                    if (icmp->type != ICMP_ECHO_REQ) {
                        printf("Not an echo request, ignoring\n");
                        continue;
                    }
                    void *buf = malloc(ETH_MTU);
                    size_t index = make_eth_hdr(buf, eth->src_mac, my_mac, 0x0800);
                    struct ip_hdr *hdr = buf + index;
                    index += make_ip_hdr(hdr, ntohs(ip->id), 1, ntohl(ip->src_ip));
                    struct icmp_pkt *pkt = buf + index;
                    size_t icmp_data_len = ntohs(ip->total_len) - sizeof(struct ip_hdr) - sizeof(struct icmp_pkt);
                    printf("total icmp data length: %i\n", icmp_data_len);
                    index += make_icmp_resp(pkt, icmp, icmp_data_len);
                    hdr->total_len = htons(index - sizeof(struct eth_hdr));
                    place_ip_chksm(hdr);
                    place_icmp_chksm(pkt, icmp_data_len);
                    write_to_wire(fd, buf, index);
                    free(buf);
                }
            }

            printf("\n");
        } else {
            printf("Read nothing - bad something\n");
        }
        memset(buf, 0, count);
    }
}

