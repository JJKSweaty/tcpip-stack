#include <arpa/inet.h>
#include <stdio.h>

#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "tcp.h"

void print_ip(uint32_t ip)
{
    struct in_addr addr;

    addr.s_addr = ip;
    printf("%s", inet_ntoa(addr));
}

void handle_ipv4(int tap_fd, uint8_t *buf, ssize_t nread)
{
    struct eth_hdr *eth;
    struct ipv4_hdr *ip;
    uint8_t version;
    uint8_t ihl;
    uint8_t ip_header_len;
    uint16_t total_len;

    if ((size_t)nread < ETH_HDR_LEN + IPV4_MIN_HDR_LEN) {
        printf("  IPv4 frame too short: %zd bytes\n", nread);
        return;
    }

    eth = (struct eth_hdr *)buf;
    ip = (struct ipv4_hdr *)eth->payload;

    version = ip->version_ihl >> 4;
    ihl = ip->version_ihl & 0x0f;
    ip_header_len = ihl * 4;

    if (version != 4) {
        printf("  Not IPv4, version=%u\n", version);
        return;
    }

    if (ip_header_len < IPV4_MIN_HDR_LEN) {
        printf("  Invalid IPv4 header length: %u\n", ip_header_len);
        return;
    }

    if ((size_t)nread < (size_t)ETH_HDR_LEN + ip_header_len) {
        printf("  IPv4 packet truncated\n");
        return;
    }

    total_len = ntohs(ip->total_len);

    if (total_len < ip_header_len) {
        printf("  Invalid IPv4 total length: %u\n", total_len);
        return;
    }

    if ((size_t)nread < (size_t)ETH_HDR_LEN + total_len) {
        printf("  IPv4 packet truncated\n");
        return;
    }

    printf("  IPv4 packet\n");

    printf("    Source IP:      ");
    print_ip(ip->saddr);
    printf("\n");

    printf("    Destination IP: ");
    print_ip(ip->daddr);
    printf("\n");

    printf("    Header length:  %u bytes\n", ip_header_len);
    printf("    Total length:   %u bytes\n", total_len);
    printf("    TTL:            %u\n", ip->ttl);

    printf("    Protocol:       %u", ip->proto);

    if (ip->proto == IP_PROTO_ICMP) {
        printf(" (ICMP)\n");
        handle_icmp(tap_fd, eth, ip, ip_header_len, total_len);
    } else if (ip->proto == IP_PROTO_TCP) {
        printf(" (TCP)\n");
        handle_tcp(tap_fd, eth, ip, ip_header_len, total_len);
    } else if (ip->proto == IP_PROTO_UDP) {
        printf(" (UDP)\n");
    } else {
        printf(" (unknown)\n");
    }
}
