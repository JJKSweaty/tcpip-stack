#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

#include "ethernet.h"
#include "ipv4.h"

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8

struct icmp_v4 {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t data[];
} __attribute__((packed));

struct icmp_v4_echo {
    uint16_t id;
    uint16_t seq;
    uint8_t data[];
} __attribute__((packed));

void handle_icmp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                 uint8_t ip_header_len, uint16_t total_len);

#endif
