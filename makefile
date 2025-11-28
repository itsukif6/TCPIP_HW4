CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = prog
SRC = ers_traceroute.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean