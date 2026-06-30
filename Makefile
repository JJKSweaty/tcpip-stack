CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude

TARGET = tcpip-stack
SRC = \
	src/main.c \
	src/tap.c \
	src/checksum.c \
	src/ethernet.c \
	src/arp.c \
	src/ipv4.c \
	src/icmp.c \
	src/udp.c \
	src/tcp.c

OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
