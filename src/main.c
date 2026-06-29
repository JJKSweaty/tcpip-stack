#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806
#define ARP_HTYPE_ETHERNET 0x0001
#define ARP_PTYPE_IPV4     0x0800
#define ARP_REQUEST        1
#define ARP_REPLY          2
#define BUFLEN 1600
#define ETH_HDR_LEN 14

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

static void print_ip(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;

    printf("%s", inet_ntoa(addr));
}

static void print_mac(uint8_t mac[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}
static void handle_arp(uint8_t *buf, ssize_t nread)
{
    if (nread < ETH_HDR_LEN + sizeof(struct arp_hdr) + sizeof(struct arp_ipv4)) {
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
}
static void handle_frame(uint8_t *buf, ssize_t nread)
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

    handle_frame(buf, nread);
}

    return 0;
}