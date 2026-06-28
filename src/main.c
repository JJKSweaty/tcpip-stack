#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

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

    while (1) {
        sleep(1);
    }

    return 0;
}