#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <sys/types.h>

#define IPV4_MIN_HDR_LEN 20
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

struct ipv4_hdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
    uint8_t payload[];
} __attribute__((packed));

void print_ip(uint32_t ip);
void handle_ipv4(int tap_fd, uint8_t *buf, ssize_t nread);

#endif
