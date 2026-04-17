CC        = gcc
CFLAGS    = -Wall -Wextra -Werror -pthread
TARGET    = biceps
TARGET_ML = biceps-memory-leaks

all: $(TARGET)

$(TARGET): biceps.c
	$(CC) $(CFLAGS) -o $(TARGET) biceps.c

memory-leak: biceps.c
	$(CC) $(CFLAGS) -g -O0 -o $(TARGET_ML) biceps.c

trace: biceps.c
	$(CC) $(CFLAGS) -DTRACE -o $(TARGET) biceps.c

trace2: biceps.c
	$(CC) $(CFLAGS) -DTRACE -DTRACE2 -o $(TARGET) biceps.c

clean:
	rm -f $(TARGET) $(TARGET_ML)

.PHONY: all memory-leak trace trace2 clean
