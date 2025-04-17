CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lnetfilter_queue

TARGET = 1m_block
SRCS = 1m_block.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS) 