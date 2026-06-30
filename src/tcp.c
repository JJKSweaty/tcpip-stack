#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "checksum.h"
#include "config.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"

struct tcp_pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tcp_len;
} __attribute__((packed));

static struct tcp_conn tcp_conn = {
    .state = TCP_STATE_CLOSED
};

static struct tcp_retransmit tcp_retx = {
    .rto_ms = TCP_RTO_INITIAL_MS
};

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

static void print_tcp_payload(uint8_t *payload, size_t payload_len)
{
    size_t i;

    printf("    TCP payload:          ");

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

static uint16_t tcp_checksum(struct ipv4_hdr *ip, struct tcp_hdr *tcp, size_t tcp_len)
{
    uint8_t buf[sizeof(struct tcp_pseudo_hdr) + tcp_len];
    struct tcp_pseudo_hdr *pseudo = (struct tcp_pseudo_hdr *)buf;

    pseudo->saddr = ip->saddr;
    pseudo->daddr = ip->daddr;
    pseudo->zero = 0;
    pseudo->proto = IP_PROTO_TCP;
    pseudo->tcp_len = htons(tcp_len);

    memcpy(buf + sizeof(struct tcp_pseudo_hdr), tcp, tcp_len);

    return checksum(buf, sizeof(struct tcp_pseudo_hdr) + tcp_len);
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void tcp_rto_update(uint32_t sample_ms)
{
    uint32_t variation;
    uint32_t safety_margin;

    if (!tcp_retx.have_rtt) {
        tcp_retx.srtt_ms = sample_ms;
        tcp_retx.rttvar_ms = sample_ms / 2;
        tcp_retx.have_rtt = true;
    } else {
        if (tcp_retx.srtt_ms > sample_ms) {
            variation = tcp_retx.srtt_ms - sample_ms;
        } else {
            variation = sample_ms - tcp_retx.srtt_ms;
        }

        tcp_retx.rttvar_ms = (3 * tcp_retx.rttvar_ms + variation) / 4;
        tcp_retx.srtt_ms = (7 * tcp_retx.srtt_ms + sample_ms) / 8;
    }

    safety_margin = 4 * tcp_retx.rttvar_ms;
    if (safety_margin < TCP_CLOCK_GRANULARITY_MS) {
        safety_margin = TCP_CLOCK_GRANULARITY_MS;
    }

    tcp_retx.rto_ms = tcp_retx.srtt_ms + safety_margin;

    if (tcp_retx.rto_ms < TCP_RTO_INITIAL_MS) {
        tcp_retx.rto_ms = TCP_RTO_INITIAL_MS;
    }

    if (tcp_retx.rto_ms > TCP_RTO_MAX_MS) {
        tcp_retx.rto_ms = TCP_RTO_MAX_MS;
    }

    printf("    RTT sample: %u ms, SRTT: %u ms, RTTVAR: %u ms, RTO: %u ms\n",
           sample_ms, tcp_retx.srtt_ms, tcp_retx.rttvar_ms, tcp_retx.rto_ms);
}

static void tcp_retransmit_queue_save(uint8_t *frame, ssize_t frame_len,
                                      uint32_t seq_start, uint32_t seq_end)
{
    if (frame_len > BUFLEN) {
        return;
    }

    memcpy(tcp_retx.frame, frame, frame_len);
    tcp_retx.frame_len = frame_len;
    tcp_retx.seq_start = seq_start;
    tcp_retx.seq_end = seq_end;
    tcp_retx.sent_ms = now_ms();
    tcp_retx.active = true;
    tcp_retx.retransmitted = false;
    tcp_retx.dup_acks = 0;

    if (tcp_retx.rto_ms == 0) {
        tcp_retx.rto_ms = TCP_RTO_INITIAL_MS;
    }

    printf("    Retransmission queued: seq %u..%u, RTO %u ms\n",
           seq_start, seq_end, tcp_retx.rto_ms);
}

void tcp_retransmit_check(int tap_fd)
{
    uint64_t elapsed_ms;

    if (!tcp_retx.active) {
        return;
    }

    elapsed_ms = now_ms() - tcp_retx.sent_ms;
    if (elapsed_ms < tcp_retx.rto_ms) {
        return;
    }

    if (write(tap_fd, tcp_retx.frame, tcp_retx.frame_len) < 0) {
        perror("write TCP retransmission");
        return;
    }

    printf("    Retransmitted TCP segment seq %u..%u after %llu ms\n",
           tcp_retx.seq_start, tcp_retx.seq_end,
           (unsigned long long)elapsed_ms);

    tcp_retx.retransmitted = true;
    tcp_retx.sent_ms = now_ms();

    if (tcp_retx.rto_ms < TCP_RTO_MAX_MS / 2) {
        tcp_retx.rto_ms *= 2;
    } else {
        tcp_retx.rto_ms = TCP_RTO_MAX_MS;
    }

    printf("    RTO backed off to %u ms\n", tcp_retx.rto_ms);
}

static void tcp_retransmit_on_ack(uint32_t ack)
{
    uint32_t sample_ms;

    if (!tcp_retx.active) {
        return;
    }

    if (ack >= tcp_retx.seq_end) {
        if (!tcp_retx.retransmitted) {
            sample_ms = (uint32_t)(now_ms() - tcp_retx.sent_ms);
            tcp_rto_update(sample_ms);
        } else {
            printf("    Karn: skipped RTT sample for retransmitted segment\n");
        }

        tcp_retx.active = false;
        tcp_retx.dup_acks = 0;
        printf("    Retransmission queue cleared\n");
    } else if (ack == tcp_conn.snd_una) {
        tcp_retx.dup_acks++;
        printf("    Duplicate ACK count: %u\n", tcp_retx.dup_acks);
    }
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

    tcp_conn.state = TCP_STATE_SYN_RECEIVED;
    tcp_conn.peer_ip = original_src_ip;
    tcp_conn.peer_port = ntohs(original_sport);
    tcp_conn.local_port = ntohs(tcp->dport);
    tcp_conn.snd_una = TCP_INITIAL_SEQ;
    tcp_conn.snd_nxt = TCP_INITIAL_SEQ + 1;
    tcp_conn.rcv_nxt = original_seq + 1;

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
    tcp->ack = htonl(tcp_conn.rcv_nxt);
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
    printf("    TCP state: SYN_RECEIVED\n");
}

static void send_tcp_ack(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                         struct tcp_hdr *tcp, uint8_t ip_header_len,
                         uint32_t seq_advance, uint8_t flags)
{
    uint32_t original_src_ip = ip->saddr;
    uint16_t original_sport = tcp->sport;
    uint32_t original_seq = ntohl(tcp->seq);
    uint32_t reply_seq = tcp_conn.snd_nxt;
    uint16_t tcp_len = sizeof(struct tcp_hdr);
    uint16_t total_len = ip_header_len + tcp_len;
    ssize_t frame_len = ETH_HDR_LEN + total_len;

    if (reply_seq == 0) {
        reply_seq = TCP_INITIAL_SEQ + 1;
    }

    tcp_conn.rcv_nxt = original_seq + seq_advance;

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
    tcp->seq = htonl(reply_seq);
    tcp->ack = htonl(tcp_conn.rcv_nxt);
    tcp->offset_reserved = (sizeof(struct tcp_hdr) / 4) << 4;
    tcp->flags = flags;
    tcp->window = htons(65535);
    tcp->urgent = 0;
    tcp->checksum = 0;
    tcp->checksum = tcp_checksum(ip, tcp, tcp_len);

    if (write(tap_fd, eth, frame_len) < 0) {
        perror("write TCP ACK");
        return;
    }

    if (flags & TCP_FIN) {
        tcp_conn.snd_nxt = reply_seq + 1;
        tcp_conn.state = TCP_STATE_LAST_ACK;
        printf("    Sent TCP FIN-ACK, advanced by %u\n", seq_advance);
        printf("    TCP state: LAST_ACK\n");
    } else {
        printf("    Sent TCP ACK, advanced by %u\n", seq_advance);
    }
}

static void send_tcp_payload(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                             struct tcp_hdr *tcp, uint8_t ip_header_len,
                             uint32_t seq_advance,
                             const uint8_t *payload, size_t payload_len)
{
    uint32_t original_src_ip = ip->saddr;
    uint16_t original_sport = tcp->sport;
    uint32_t original_seq = ntohl(tcp->seq);
    uint32_t reply_seq = tcp_conn.snd_nxt;
    uint16_t tcp_len = sizeof(struct tcp_hdr) + payload_len;
    uint16_t total_len = ip_header_len + tcp_len;
    ssize_t frame_len = ETH_HDR_LEN + total_len;

    if (reply_seq == 0) {
        reply_seq = TCP_INITIAL_SEQ + 1;
    }

    tcp_conn.rcv_nxt = original_seq + seq_advance;

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
    tcp->seq = htonl(reply_seq);
    tcp->ack = htonl(tcp_conn.rcv_nxt);
    tcp->offset_reserved = (sizeof(struct tcp_hdr) / 4) << 4;
    tcp->flags = TCP_ACK | TCP_PSH;
    tcp->window = htons(65535);
    tcp->urgent = 0;
    memcpy(tcp->data, payload, payload_len);
    tcp->checksum = 0;
    tcp->checksum = tcp_checksum(ip, tcp, tcp_len);

    if (write(tap_fd, eth, frame_len) < 0) {
        perror("write TCP payload");
        return;
    }

    tcp_conn.snd_nxt = reply_seq + payload_len;
    printf("    Sent TCP payload: %zu bytes\n", payload_len);
    printf("    SND.NXT: %u\n", tcp_conn.snd_nxt);

    tcp_retransmit_queue_save((uint8_t *)eth, frame_len,
                              reply_seq, tcp_conn.snd_nxt);
}

void handle_tcp(int tap_fd, struct eth_hdr *eth, struct ipv4_hdr *ip,
                uint8_t ip_header_len, uint16_t total_len)
{
    size_t tcp_len;
    size_t tcp_payload_len;
    uint32_t seq_advance;
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

    tcp_payload_len = tcp_len - tcp_header_len;

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
    printf("    TCP payload length:   %zu bytes\n", tcp_payload_len);

    if (tcp_payload_len > 0) {
        print_tcp_payload((uint8_t *)tcp + tcp_header_len, tcp_payload_len);
    }

    if (ip->daddr != stack_ip) {
        printf("    TCP segment not for us\n");
        return;
    }

    if ((tcp->flags & TCP_SYN) && !(tcp->flags & TCP_ACK)) {
        send_tcp_syn_ack(tap_fd, eth, ip, tcp, ip_header_len);
    } else if (tcp_payload_len > 0 || (tcp->flags & TCP_FIN)) {
        uint8_t reply_flags = TCP_ACK;

        seq_advance = tcp_payload_len;

        if (tcp->flags & TCP_FIN) {
            printf("    TCP FIN received\n");
            seq_advance += 1;
            reply_flags |= TCP_FIN;
        }

        if (tcp_payload_len > 0 && !(tcp->flags & TCP_FIN)) {
            send_tcp_payload(tap_fd, eth, ip, tcp, ip_header_len,
                             seq_advance,
                             (const uint8_t *)TCP_RESPONSE,
                             strlen(TCP_RESPONSE));
        } else {
            send_tcp_ack(tap_fd, eth, ip, tcp, ip_header_len,
                         seq_advance, reply_flags);
        }
    } else if ((tcp->flags & TCP_ACK) && tcp_payload_len == 0) {
        uint32_t ack = ntohl(tcp->ack);

        printf("    TCP pure ACK received\n");

        if (tcp_conn.state == TCP_STATE_SYN_RECEIVED &&
            ack == tcp_conn.snd_nxt) {
            tcp_conn.snd_una = ack;
            tcp_conn.state = TCP_STATE_ESTABLISHED;
            printf("    SND.UNA: %u\n", tcp_conn.snd_una);
            printf("    TCP state: ESTABLISHED\n");
        } else if (tcp_conn.state == TCP_STATE_LAST_ACK &&
                   ack == tcp_conn.snd_nxt) {
            tcp_conn.snd_una = ack;
            tcp_conn.state = TCP_STATE_CLOSED;
            printf("    SND.UNA: %u\n", tcp_conn.snd_una);
            printf("    TCP state: CLOSED\n");
        } else if (ack > tcp_conn.snd_una &&
                   ack <= tcp_conn.snd_nxt) {
            tcp_conn.snd_una = ack;
            printf("    SND.UNA: %u\n", tcp_conn.snd_una);
        }

        tcp_retransmit_on_ack(ack);
    }
}
