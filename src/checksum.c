#include "checksum.h"

uint16_t checksum(void *data, size_t len)
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
