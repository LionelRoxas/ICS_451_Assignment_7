CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = server
SRCS = server.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)

.PHONY: all clean