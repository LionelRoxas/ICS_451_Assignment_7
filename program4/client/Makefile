CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = client
SRCS = client.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)

.PHONY: all clean