CC = gcc
CFLAGS = -Wall -g -Iinc
LDFLAGS = -lssl -lcrypto

TARGET = cryptopals
SRCS = main.c $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
