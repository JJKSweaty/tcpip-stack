#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <sys/types.h>

#include "ethernet.h"

#define ARP_HTYPE_ETHERNET 0x0001
#define ARP_PTYPE_IPV4     0x0800
#define ARP_REQUEST        1
#define ARP_REPLY          2

struct arp_hdr {
    uint16_t hwtype;
    uint16_t protype;
    uint8_t hwsize;
    uint8_t prosize;
    uint16_t opcode;
    uint8_t data[];
} __attribute__((packed));

struct arp_ipv4 {
    uint8_t smac[6];
    uint32_t sip;
    uint8_t dmac[6];
    uint32_t dip;
} __attribute__((packed));

void send_arp_reply(int tap_fd, struct eth_hdr *req_eth,
                    struct arp_ipv4 *req_data);
void handle_arp(int tap_fd, uint8_t *buf, ssize_t nread);

#endif
