CC = gcc
CFLAGS = -Wall -g -pthread

# Numele executabilului
TARGET = dns_server

SRC = dns_server_bun.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)