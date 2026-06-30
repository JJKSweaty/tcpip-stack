#ifndef UDP_H
#define UDP_H

#include <stdint.h>

#include "ethernet.h"
#include "ipv4.h"

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
    uint8_t data[];
} __attribute__((packed));

void handle_udp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                uint8_t ip_header_len, uint16_t total_len);

#endif
