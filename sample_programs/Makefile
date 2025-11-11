CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -pthread

PROGRAMS = hello cpu_intensive memory_test infinite_loop file_operations \
           fork_bomb file_spammer memory_bomb cpu_abuse disk_filler resource_exhaustion

.PHONY: all clean

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ -pthread

clean:
	rm -f $(PROGRAMS)

