#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "checksum.h"
#include "config.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"

static void send_icmp_echo_reply(int tap_fd, struct eth_hdr *eth,
                                 struct ipv4_hdr *ip,
                                 uint8_t ip_header_len,
                                 uint16_t total_len)
{
    size_t icmp_len = total_len - ip_header_len;
    struct icmp_v4 *icmp = (struct icmp_v4 *)((uint8_t *)ip + ip_header_len);
    uint32_t original_src_ip = ip->saddr;
    ssize_t frame_len = ETH_HDR_LEN + total_len;

    memcpy(eth->dmac, eth->smac, 6);
    memcpy(eth->smac, stack_mac, 6);

    ip->saddr = stack_ip;
    ip->daddr = original_src_ip;
    ip->ttl = 64;
    ip->checksum = 0;
    ip->checksum = checksum(ip, ip_header_len);

    icmp->type = ICMP_ECHO_REPLY;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, icmp_len);

    if (write(tap_fd, eth, frame_len) < 0) {
        perror("write ICMP echo reply");
        return;
    }

    printf("    Sent ICMP echo reply\n");
}

void handle_icmp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                 uint8_t ip_header_len, uint16_t total_len)
{
    struct icmp_v4 *icmp;
    struct icmp_v4_echo *echo;
    size_t icmp_len;

    if (total_len < ip_header_len + sizeof(struct icmp_v4)) {
        printf("    ICMP packet too short\n");
        return;
    }

    icmp_len = total_len - ip_header_len;
    icmp = (struct icmp_v4 *)((uint8_t *)ip + ip_header_len);

    printf("    ICMP type:      %u", icmp->type);

    if (icmp->type == ICMP_ECHO_REQUEST) {
        printf(" (echo request)\n");
    } else if (icmp->type == ICMP_ECHO_REPLY) {
        printf(" (echo reply)\n");
    } else {
        printf(" (other)\n");
    }

    printf("    ICMP code:      %u\n", icmp->code);
    printf("    ICMP checksum:  0x%04x\n", ntohs(icmp->checksum));

    if (icmp->type != ICMP_ECHO_REQUEST && icmp->type != ICMP_ECHO_REPLY) {
        return;
    }

    if (icmp_len < sizeof(struct icmp_v4) + sizeof(struct icmp_v4_echo)) {
        printf("    ICMP echo data too short\n");
        return;
    }

    echo = (struct icmp_v4_echo *)icmp->data;

    printf("    Echo id:        %u\n", ntohs(echo->id));
    printf("    Echo sequence:  %u\n", ntohs(echo->seq));

    if (icmp->type != ICMP_ECHO_REQUEST) {
        return;
    }

    if (ip->daddr != stack_ip) {
        printf("    ICMP echo request not for us\n");
        return;
    }

    send_icmp_echo_reply(tap_fd, eth, ip, ip_header_len, total_len);
}
