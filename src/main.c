#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806

#define ARP_HTYPE_ETHERNET 0x0001
#define ARP_PTYPE_IPV4     0x0800
#define ARP_REQUEST        1
#define ARP_REPLY          2
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFLEN 1600
#define ETH_HDR_LEN 14

struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

static void print_mac(uint8_t mac[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
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