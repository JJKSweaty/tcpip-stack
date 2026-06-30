#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "checksum.h"
#include "config.h"
#include "ethernet.h"
#include "ipv4.h"
#include "udp.h"

struct udp_pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t udp_len;
} __attribute__((packed));

static void print_udp_payload(uint8_t *payload, size_t payload_len)
{
    size_t i;

    printf("    UDP payload:          ");

    for (i = 0; i < payload_len; i++) {
        uint8_t c = payload[i];

        if (c >= 32 && c <= 126) {
            putchar(c);
        } else if (c == '\n') {
            printf("\\n");
        } else if (c == '\r') {
            printf("\\r");
        } else {
            putchar('.');
        }
    }

    printf("\n");
}

static uint16_t udp_checksum(struct ipv4_hdr *ip, struct udp_hdr *udp,
                             size_t udp_len)
{
    uint8_t buf[sizeof(struct udp_pseudo_hdr) + udp_len];
    struct udp_pseudo_hdr *pseudo = (struct udp_pseudo_hdr *)buf;

    pseudo->saddr = ip->saddr;
    pseudo->daddr = ip->daddr;
    pseudo->zero = 0;
    pseudo->proto = IP_PROTO_UDP;
    pseudo->udp_len = htons(udp_len);

    memcpy(buf + sizeof(struct udp_pseudo_hdr), udp, udp_len);

    return checksum(buf, sizeof(struct udp_pseudo_hdr) + udp_len);
}

static void send_udp_echo_reply(int tap_fd, struct eth_hdr *eth,
                                struct ipv4_hdr *ip, struct udp_hdr *udp,
                                uint8_t ip_header_len, uint16_t udp_len)
{
    uint32_t original_src_ip = ip->saddr;
    uint16_t original_sport = udp->sport;
    uint16_t total_len = ip_header_len + udp_len;
    ssize_t frame_len = ETH_HDR_LEN + total_len;

    memcpy(eth->dmac, eth->smac, 6);
    memcpy(eth->smac, stack_mac, 6);

    ip->saddr = stack_ip;
    ip->daddr = original_src_ip;
    ip->ttl = 64;
    ip->total_len = htons(total_len);
    ip->checksum = 0;
    ip->checksum = checksum(ip, ip_header_len);

    udp->sport = udp->dport;
    udp->dport = original_sport;
    udp->len = htons(udp_len);
    udp->checksum = 0;
    udp->checksum = udp_checksum(ip, udp, udp_len);

    if (write(tap_fd, eth, frame_len) < 0) {
        perror("write UDP echo reply");
        return;
    }

    printf("    Sent UDP echo reply: %u bytes\n",
           (unsigned int)(udp_len - sizeof(struct udp_hdr)));
}

void handle_udp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                uint8_t ip_header_len, uint16_t total_len)
{
    struct udp_hdr *udp;
    uint16_t udp_len;
    size_t udp_payload_len;

    if (total_len < ip_header_len + sizeof(struct udp_hdr)) {
        printf("    UDP datagram too short\n");
        return;
    }

    udp = (struct udp_hdr *)((uint8_t *)ip + ip_header_len);
    udp_len = ntohs(udp->len);

    if (udp_len < sizeof(struct udp_hdr)) {
        printf("    Invalid UDP length: %u\n", udp_len);
        return;
    }

    if (total_len < ip_header_len + udp_len) {
        printf("    UDP datagram truncated\n");
        return;
    }

    udp_payload_len = udp_len - sizeof(struct udp_hdr);

    printf("    UDP source port:      %u\n", ntohs(udp->sport));
    printf("    UDP destination port: %u\n", ntohs(udp->dport));
    printf("    UDP length:           %u bytes\n", udp_len);
    printf("    UDP checksum:         0x%04x\n", ntohs(udp->checksum));
    printf("    UDP payload length:   %zu bytes\n", udp_payload_len);

    if (udp_payload_len > 0) {
        print_udp_payload(udp->data, udp_payload_len);
    }

    if (ip->daddr != stack_ip) {
        printf("    UDP datagram not for us\n");
        return;
    }

    if (udp_payload_len == 0) {
        printf("    Empty UDP datagram, no reply sent\n");
        return;
    }

    send_udp_echo_reply(tap_fd, eth, ip, udp, ip_header_len, udp_len);
}
