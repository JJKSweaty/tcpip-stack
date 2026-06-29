#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define IPV4_MIN_HDR_LEN 20
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17
#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806
#define ARP_HTYPE_ETHERNET 0x0001
#define ARP_PTYPE_IPV4     0x0800
#define ARP_REQUEST        1
#define ARP_REPLY          2
#define BUFLEN 1600
#define ETH_HDR_LEN 14
#define STACK_IP "10.0.0.2"
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_INITIAL_SEQ 1000
static uint32_t stack_ip;
static uint8_t stack_mac[6] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02
};


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

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
    uint8_t data[];
} __attribute__((packed));

struct tcp_pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tcp_len;
} __attribute__((packed));

struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

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
static void handle_icmp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                        uint8_t ip_header_len, uint16_t total_len);
static void handle_ipv4(int tap_fd, uint8_t *buf, ssize_t nread);
static void handle_tcp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                       uint8_t ip_header_len, uint16_t total_len);
static void print_ip(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;

    printf("%s", inet_ntoa(addr));
}
static uint16_t checksum(void *data, size_t len)
{
    uint32_t sum = 0;
    uint16_t *word = data;

    while (len > 1) {
        sum += *word++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)word;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

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

static void handle_icmp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
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

static void print_tcp_flags(uint8_t flags)
{
    if (flags & TCP_FIN) {
        printf(" FIN");
    }
    if (flags & TCP_SYN) {
        printf(" SYN");
    }
    if (flags & TCP_RST) {
        printf(" RST");
    }
    if (flags & TCP_PSH) {
        printf(" PSH");
    }
    if (flags & TCP_ACK) {
        printf(" ACK");
    }
    if (flags & TCP_URG) {
        printf(" URG");
    }
}

static uint16_t tcp_checksum(struct ipv4_hdr *ip, struct tcp_hdr *tcp, size_t tcp_len)
{
    uint8_t buf[sizeof(struct tcp_pseudo_hdr) + sizeof(struct tcp_hdr)];
    struct tcp_pseudo_hdr *pseudo = (struct tcp_pseudo_hdr *)buf;

    pseudo->saddr = ip->saddr;
    pseudo->daddr = ip->daddr;
    pseudo->zero = 0;
    pseudo->proto = IP_PROTO_TCP;
    pseudo->tcp_len = htons(tcp_len);

    memcpy(buf + sizeof(struct tcp_pseudo_hdr), tcp, tcp_len);

    return checksum(buf, sizeof(struct tcp_pseudo_hdr) + tcp_len);
}

static void send_tcp_syn_ack(int tap_fd, struct eth_hdr *eth,
                             struct ipv4_hdr *ip, struct tcp_hdr *tcp,
                             uint8_t ip_header_len)
{
    uint32_t original_src_ip = ip->saddr;
    uint16_t original_sport = tcp->sport;
    uint32_t original_seq = ntohl(tcp->seq);
    uint16_t tcp_len = sizeof(struct tcp_hdr);
    uint16_t total_len = ip_header_len + tcp_len;
    ssize_t frame_len = ETH_HDR_LEN + total_len;

    memcpy(eth->dmac, eth->smac, 6);
    memcpy(eth->smac, stack_mac, 6);

    ip->saddr = stack_ip;
    ip->daddr = original_src_ip;
    ip->ttl = 64;
    ip->total_len = htons(total_len);
    ip->checksum = 0;
    ip->checksum = checksum(ip, ip_header_len);

    tcp->sport = tcp->dport;
    tcp->dport = original_sport;
    tcp->seq = htonl(TCP_INITIAL_SEQ);
    tcp->ack = htonl(original_seq + 1);
    tcp->offset_reserved = (sizeof(struct tcp_hdr) / 4) << 4;
    tcp->flags = TCP_SYN | TCP_ACK;
    tcp->window = htons(65535);
    tcp->urgent = 0;
    tcp->checksum = 0;
    tcp->checksum = tcp_checksum(ip, tcp, tcp_len);

    if (write(tap_fd, eth, frame_len) < 0) {
        perror("write TCP SYN-ACK");
        return;
    }

    printf("    Sent TCP SYN-ACK\n");
}

static void handle_tcp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                       uint8_t ip_header_len, uint16_t total_len)
{
    size_t tcp_len;
    struct tcp_hdr *tcp;
    uint8_t tcp_header_len;

    if (total_len < ip_header_len + sizeof(struct tcp_hdr)) {
        printf("    TCP segment too short\n");
        return;
    }

    tcp_len = total_len - ip_header_len;
    tcp = (struct tcp_hdr *)((uint8_t *)ip + ip_header_len);
    tcp_header_len = (tcp->offset_reserved >> 4) * 4;

    if (tcp_header_len < sizeof(struct tcp_hdr)) {
        printf("    Invalid TCP header length: %u\n", tcp_header_len);
        return;
    }

    if (tcp_len < tcp_header_len) {
        printf("    TCP segment truncated\n");
        return;
    }

    printf("    TCP source port:      %u\n", ntohs(tcp->sport));
    printf("    TCP destination port: %u\n", ntohs(tcp->dport));
    printf("    TCP sequence:         %u\n", ntohl(tcp->seq));
    printf("    TCP acknowledgment:   %u\n", ntohl(tcp->ack));
    printf("    TCP header length:    %u bytes\n", tcp_header_len);
    printf("    TCP flags:            0x%02x", tcp->flags);
    print_tcp_flags(tcp->flags);
    printf("\n");
    printf("    TCP window:           %u\n", ntohs(tcp->window));
    printf("    TCP checksum:         0x%04x\n", ntohs(tcp->checksum));

    if (ip->daddr != stack_ip) {
        printf("    TCP segment not for us\n");
        return;
    }

    if ((tcp->flags & TCP_SYN) && !(tcp->flags & TCP_ACK)) {
        send_tcp_syn_ack(tap_fd, eth, ip, tcp, ip_header_len);
    }
}


static void send_arp_reply(int tap_fd,
                           struct eth_hdr *req_eth,
                           struct arp_ipv4 *req_data)
{
    uint8_t reply[ETH_HDR_LEN + sizeof(struct arp_hdr) + sizeof(struct arp_ipv4)];

    struct eth_hdr *eth = (struct eth_hdr *)reply;
    struct arp_hdr *arp = (struct arp_hdr *)eth->payload;
    struct arp_ipv4 *arp_data = (struct arp_ipv4 *)arp->data;

    // Ethernet header
    memcpy(eth->dmac, req_eth->smac, 6);
    memcpy(eth->smac, stack_mac, 6);
    eth->ethertype = htons(ETH_P_ARP);

    // ARP header
    arp->hwtype = htons(ARP_HTYPE_ETHERNET);
    arp->protype = htons(ARP_PTYPE_IPV4);
    arp->hwsize = 6;
    arp->prosize = 4;
    arp->opcode = htons(ARP_REPLY);

    // ARP IPv4 body
    memcpy(arp_data->smac, stack_mac, 6);
    arp_data->sip = stack_ip;

    memcpy(arp_data->dmac, req_data->smac, 6);
    arp_data->dip = req_data->sip;

    ssize_t written = write(tap_fd, reply, sizeof(reply));

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

static void print_mac(uint8_t mac[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}
static void handle_arp(int tap_fd, uint8_t *buf, ssize_t nread)
{
    size_t arp_frame_len = ETH_HDR_LEN + sizeof(struct arp_hdr) + sizeof(struct arp_ipv4);

    if ((size_t)nread < arp_frame_len) {
        printf("ARP frame too short: %zd bytes\n", nread);
        return;
    }

    struct eth_hdr *eth = (struct eth_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)eth->payload;
    struct arp_ipv4 *arp_data = (struct arp_ipv4 *)arp->data;

    uint16_t hwtype = ntohs(arp->hwtype);
    uint16_t protype = ntohs(arp->protype);
    uint16_t opcode = ntohs(arp->opcode);

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

static void handle_frame(int tap_fd, uint8_t *buf, ssize_t nread)
{
    if (nread < ETH_HDR_LEN) {
        printf("Frame too short: %zd bytes\n", nread);
        return;
    }

    struct eth_hdr *eth = (struct eth_hdr *)buf;
    uint16_t ethertype = ntohs(eth->ethertype);

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
    }else if (ethertype == ETH_P_IP) {
        handle_ipv4(tap_fd, buf, nread);
    } else {
        printf("  Unknown EtherType, ignoring for now\n");
    }
}

static void handle_ipv4(int tap_fd, uint8_t *buf, ssize_t nread)
{
    if ((size_t)nread < ETH_HDR_LEN + IPV4_MIN_HDR_LEN) {
        printf("  IPv4 frame too short: %zd bytes\n", nread);
        return;
    }

    struct eth_hdr *eth = (struct eth_hdr *)buf;
    struct ipv4_hdr *ip = (struct ipv4_hdr *)eth->payload;

    uint8_t version = ip->version_ihl >> 4;
    uint8_t ihl = ip->version_ihl & 0x0f;
    uint8_t ip_header_len = ihl * 4;

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

    uint16_t total_len = ntohs(ip->total_len);

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

static int tap_alloc(char *dev)
{
    struct ifreq ifr;
    int fd;
    int err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (dev[0] != '\0') {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    }

    err = ioctl(fd, TUNSETIFF, &ifr);
    if (err < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int main(void)
{
    char dev[IFNAMSIZ] = "tap0";

    int tap_fd = tap_alloc(dev);
    stack_ip = inet_addr(STACK_IP);
    printf("Created TAP device: %s\n", dev);
    printf("tap_fd = %d\n", tap_fd);
    printf("Press Ctrl+C to exit.\n");

    uint8_t buf[BUFLEN];

while (1) {
    ssize_t nread = read(tap_fd, buf, sizeof(buf));

    if (nread < 0) {
        if (errno == EINTR) {
            continue;
        }

        perror("read");
        break;
    }

    handle_frame(tap_fd,buf, nread);
}

    return 0;
}
