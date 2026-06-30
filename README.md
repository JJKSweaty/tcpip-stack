# tcpip-stack

A small userspace TCP/IP stack in C on Linux/WSL2 using a TAP device.

This project follows Saminiir's "Let's code a TCP/IP stack" series as a
learning path, then grows it into a clear educational codebase that can become
a public reference, portfolio project, and tutorial series.

## Packet Path

Packets enter from the TAP device as Ethernet frames:

```text
TAP device
  -> Ethernet frame
     -> ARP packet
     -> IPv4 packet
        -> ICMP packet
        -> UDP datagram
        -> TCP segment
           -> TCP payload bytes
```

The code is split to match that path:

```text
src/main.c        program entry and select() event loop
src/tap.c         TAP device setup
src/ethernet.c    Ethernet parsing and dispatch
src/arp.c         ARP request parsing and replies
src/ipv4.c        IPv4 parsing and protocol dispatch
src/icmp.c        ICMP echo request/reply handling
src/udp.c         UDP parsing and echo replies
src/tcp.c         minimal TCP state, data response, retransmission timer
src/checksum.c    Internet checksum helper
```

The matching headers live in `include/`.

## What It Supports

- TAP device named `tap0`
- Stack IP: `10.0.0.2`
- Host/Linux side IP: `10.0.0.1`
- Stack MAC: `02:00:00:00:00:02`
- Ethernet frame parsing
- ARP request parsing and ARP replies
- IPv4 packet parsing
- ICMP echo replies for `ping`
- UDP header parsing
- UDP payload receive and print
- UDP echo replies using the same payload bytes
- TCP header parsing
- Minimal TCP SYN, SYN-ACK, ACK handshake
- TCP payload receive and print
- Hardcoded TCP payload response: `stack received\n`
- TCP FIN/FIN-ACK close handling
- One-connection TCP control block
- One-segment retransmission queue
- Integer millisecond SRTT, RTTVAR, and RTO tracking
- RTO backoff on timeout
- Karn's rule for retransmitted segments

## What It Does Not Support Yet

- Multiple simultaneous TCP connections
- TCP options
- TCP receive window management
- Out-of-order TCP segments
- Real socket API integration
- UDP sockets or port binding
- UDP fragmentation/reassembly
- IPv6
- Automated packet-level tests

## How The Layers Fit Together

Ethernet is the outer layer. It tells the stack whether the payload is ARP or
IPv4 by reading the EtherType field.

ARP is used before IP traffic can work. Linux asks, "Who has `10.0.0.2`?" and
the stack replies with `02:00:00:00:00:02`.

IPv4 is the next dispatcher. It checks the IPv4 header and then sends the
payload to ICMP, UDP, or TCP based on the protocol number.

ICMP is used by `ping`. The stack changes an echo request into an echo reply
and sends it back.

UDP is connectionless. There is no handshake, sequence number, or retransmission
queue. This stack prints the UDP header and payload, then sends the same payload
back as a UDP echo reply.

TCP is stateful. This stack keeps one tiny connection control block, performs a
minimal handshake, replies with `stack received\n`, handles FIN close, and keeps
one outbound payload queued for retransmission.

## Build

```bash
make
```

Clean generated files:

```bash
make clean
```

## Run The Stack

Terminal 1:

```bash
make
sudo ./tcpip-stack
```

The program creates `tap0` and then waits for packets.

## Configure TAP

Terminal 2:

```bash
sudo ip link set tap0 up
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip neigh flush dev tap0
```

If the address already exists:

```bash
sudo ip addr show dev tap0
```

Either keep the existing `10.0.0.1/24` address, or reset it:

```bash
sudo ip addr del 10.0.0.1/24 dev tap0
sudo ip addr add 10.0.0.1/24 dev tap0
```

## Ping Test

Terminal 2:

```bash
ping -c 3 10.0.0.2
```

Check the ARP neighbor entry:

```bash
ip neigh show dev tap0
```

Expected entry:

```text
10.0.0.2 lladdr 02:00:00:00:00:02
```

## TCP Test

Terminal 2:

```bash
printf 'hello tcp\n' | nc -w 2 10.0.0.2 1337
```

Expected client output:

```text
stack received
```

The stack should print the TCP handshake, payload bytes, ACK advancement, and
connection close path.

## UDP Test

Terminal 2:

```bash
printf 'hello udp\n' | nc -u -w 1 10.0.0.2 1337
```

Expected client output:

```text
hello udp
```

The stack should print the UDP source port, destination port, length, checksum,
payload bytes, and echo reply message.

## Retransmission Test Idea

Use a temporary firewall rule to drop ACKs on `tap0`, then run the TCP test and
watch the stack log its retransmission queue, timeout, and RTO backoff.

Do this manually because it changes the host network namespace. Remove the rule
after the test.

## Roadmap

- Continue cleaning file structure as the stack grows
- Add automated tests for checksums and packet handlers
- Add diagrams for Ethernet, ARP, IPv4, ICMP, and TCP packet layouts
- Add packet walkthroughs with captured bytes and screenshots
- Add TCP options
- Add multi-connection support
- Add fuller UDP examples, such as simple request/response protocols
- Explore IPv6 later
