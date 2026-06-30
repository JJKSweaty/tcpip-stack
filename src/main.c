#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>

#include "config.h"
#include "ethernet.h"
#include "tap.h"
#include "tcp.h"

uint32_t stack_ip;
uint8_t stack_mac[6] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02
};

int main(void)
{
    char dev[IFNAMSIZ] = "tap0";
    int tap_fd;
    uint8_t buf[BUFLEN];

    tap_fd = tap_alloc(dev);
    stack_ip = inet_addr(STACK_IP);

    printf("Created TAP device: %s\n", dev);
    printf("tap_fd = %d\n", tap_fd);
    printf("Press Ctrl+C to exit.\n");

    while (1) {
        fd_set readfds;
        struct timeval timeout;
        int ready;

        FD_ZERO(&readfds);
        FD_SET(tap_fd, &readfds);

        timeout.tv_sec = 0;
        timeout.tv_usec = TCP_TIMER_TICK_MS * 1000;

        ready = select(tap_fd + 1, &readfds, NULL, NULL, &timeout);

        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }

            perror("select");
            break;
        }

        if (ready > 0 && FD_ISSET(tap_fd, &readfds)) {
            ssize_t nread = read(tap_fd, buf, sizeof(buf));

            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }

                perror("read");
                break;
            }

            handle_frame(tap_fd, buf, nread);
        }

        tcp_retransmit_check(tap_fd);
    }

    return 0;
}
