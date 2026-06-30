#include <arpa/inet.h>
#include <stdio.h>

#include "arp.h"
#include "ethernet.h"
#include "ipv4.h"

void print_mac(uint8_t mac[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void handle_frame(int tap_fd, uint8_t *buf, ssize_t nread)
{
    struct eth_hdr *eth;
    uint16_t ethertype;

    if (nread < ETH_HDR_LEN) {
        printf("Frame too short: %zd bytes\n", nread);
        return;
    }

    eth = (struct eth_hdr *)buf;
    ethertype = ntohs(eth->ethertype);

    printf("\nEthernet frame: %zd bytes\n", nread);

    printf("  Destination MAC: ");
    print_mac(eth->dmac);
    printf("\n");

    printf("  Source MAC:      ");
    print_mac(eth->smac);
    printf("\n");

    printf("  EtherType:       0x%04x\n", ethertype);

    if (ethertype == ETH_P_ARP) {
        handle_arp(tap_fd, buf, nread);
    } else if (ethertype == ETH_P_IP) {
        handle_ipv4(tap_fd, buf, nread);
    } else {
        printf("  Unknown EtherType, ignoring for now\n");
    }
}
