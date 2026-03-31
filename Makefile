CC      = gcc
CFLAGS  = -Wall -Wextra -pthread
TARGET  = biceps

all: $(TARGET)

$(TARGET): biceps.c
	$(CC) $(CFLAGS) -o $(TARGET) biceps.c

# Compilation avec traces niveau 1
trace: biceps.c
	$(CC) $(CFLAGS) -DTRACE -o $(TARGET) biceps.c

# Compilation avec traces niveau 1 et 2
trace2: biceps.c
	$(CC) $(CFLAGS) -DTRACE -DTRACE2 -o $(TARGET) biceps.c

clean:
	rm -f $(TARGET)

.PHONY: all trace trace2 clean
