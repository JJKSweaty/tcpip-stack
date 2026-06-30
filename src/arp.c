#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "arp.h"
#include "config.h"
#include "ethernet.h"
#include "ipv4.h"

void send_arp_reply(int tap_fd,
                    struct eth_hdr *req_eth,
                    struct arp_ipv4 *req_data)
{
    uint8_t reply[ETH_HDR_LEN + sizeof(struct arp_hdr) + sizeof(struct arp_ipv4)];
    struct eth_hdr *eth = (struct eth_hdr *)reply;
    struct arp_hdr *arp = (struct arp_hdr *)eth->payload;
    struct arp_ipv4 *arp_data = (struct arp_ipv4 *)arp->data;
    ssize_t written;

    memcpy(eth->dmac, req_eth->smac, 6);
    memcpy(eth->smac, stack_mac, 6);
    eth->ethertype = htons(ETH_P_ARP);

    arp->hwtype = htons(ARP_HTYPE_ETHERNET);
    arp->protype = htons(ARP_PTYPE_IPV4);
    arp->hwsize = 6;
    arp->prosize = 4;
    arp->opcode = htons(ARP_REPLY);

    memcpy(arp_data->smac, stack_mac, 6);
    arp_data->sip = stack_ip;

    memcpy(arp_data->dmac, req_data->smac, 6);
    arp_data->dip = req_data->sip;

    written = write(tap_fd, reply, sizeof(reply));
    if (written < 0) {
        perror("write ARP reply");
        return;
    }

    printf("    Sent ARP reply\n");
}

static bool arp_is_valid_request(struct arp_hdr *arp, struct arp_ipv4 *arp_data)
{
    uint16_t hwtype = ntohs(arp->hwtype);
    uint16_t protype = ntohs(arp->protype);
    uint16_t opcode = ntohs(arp->opcode);

    if (hwtype != ARP_HTYPE_ETHERNET) {
        return false;
    }

    if (protype != ARP_PTYPE_IPV4) {
        return false;
    }

    if (arp->hwsize != 6) {
        return false;
    }

    if (arp->prosize != 4) {
        return false;
    }

    if (opcode != ARP_REQUEST) {
        return false;
    }

    if (arp_data->dip != stack_ip) {
        return false;
    }

    return true;
}

void handle_arp(int tap_fd, uint8_t *buf, ssize_t nread)
{
    size_t arp_frame_len = ETH_HDR_LEN + sizeof(struct arp_hdr) + sizeof(struct arp_ipv4);
    struct eth_hdr *eth;
    struct arp_hdr *arp;
    struct arp_ipv4 *arp_data;
    uint16_t hwtype;
    uint16_t protype;
    uint16_t opcode;

    if ((size_t)nread < arp_frame_len) {
        printf("ARP frame too short: %zd bytes\n", nread);
        return;
    }

    eth = (struct eth_hdr *)buf;
    arp = (struct arp_hdr *)eth->payload;
    arp_data = (struct arp_ipv4 *)arp->data;

    hwtype = ntohs(arp->hwtype);
    protype = ntohs(arp->protype);
    opcode = ntohs(arp->opcode);

    printf("  ARP packet\n");
    printf("    Hardware type: 0x%04x\n", hwtype);
    printf("    Protocol type: 0x%04x\n", protype);
    printf("    Hardware size: %u\n", arp->hwsize);
    printf("    Protocol size: %u\n", arp->prosize);
    printf("    Opcode:        %u", opcode);

    if (opcode == ARP_REQUEST) {
        printf(" (request)\n");
    } else if (opcode == ARP_REPLY) {
        printf(" (reply)\n");
    } else {
        printf(" (unknown)\n");
    }

    printf("    Sender MAC:    ");
    print_mac(arp_data->smac);
    printf("\n");

    printf("    Sender IP:     ");
    print_ip(arp_data->sip);
    printf("\n");

    printf("    Target MAC:    ");
    print_mac(arp_data->dmac);
    printf("\n");

    printf("    Target IP:     ");
    print_ip(arp_data->dip);
    printf("\n");

    if (arp_is_valid_request(arp, arp_data)) {
        printf("    Result: valid ARP request for us\n");
        send_arp_reply(tap_fd, eth, arp_data);
    } else {
        printf("    Result: ignored ARP packet\n");
    }
}
