#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <sys/types.h>

#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806
#define ETH_HDR_LEN 14

struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

void print_mac(uint8_t mac[6]);
void handle_frame(int tap_fd, uint8_t *buf, ssize_t nread);

#endif
