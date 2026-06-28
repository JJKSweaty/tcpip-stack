CC = gcc
CFLAGS = -Wall -Wextra -g

TARGET = tcpip-stack
SRC = src/main.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)