#ifndef TCP_H
#define TCP_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#include "ethernet.h"
#include "ipv4.h"

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_INITIAL_SEQ 1000
#define TCP_RESPONSE "stack received\n"
#define TCP_RTO_INITIAL_MS 1000
#define TCP_RTO_MAX_MS 60000
#define TCP_CLOCK_GRANULARITY_MS 100
#define TCP_TIMER_TICK_MS 100

enum tcp_state {
    TCP_STATE_CLOSED,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_LAST_ACK
};

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

struct tcp_conn {
    enum tcp_state state;
    uint32_t peer_ip;
    uint16_t peer_port;
    uint16_t local_port;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
};

struct tcp_retransmit {
    bool active;
    bool retransmitted;
    uint8_t frame[BUFLEN];
    ssize_t frame_len;
    uint32_t seq_start;
    uint32_t seq_end;
    uint64_t sent_ms;
    bool have_rtt;
    uint32_t srtt_ms;
    uint32_t rttvar_ms;
    uint32_t rto_ms;
    uint32_t dup_acks;
};

void handle_tcp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                uint8_t ip_header_len, uint16_t total_len);
void tcp_retransmit_check(int tap_fd);

#endif
