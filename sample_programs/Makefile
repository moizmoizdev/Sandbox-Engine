CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -pthread

# Original programs
PROGRAMS = hello cpu_intensive memory_test infinite_loop file_operations \
           fork_bomb file_spammer memory_bomb cpu_abuse disk_filler resource_exhaustion \
           network_test http_request dns_lookup port_scan

# New security test programs
SECURITY_PROGRAMS = stack_test mmap_exec_test mprotect_test network_connect \
                    syscall_test print_info

ALL_PROGRAMS = $(PROGRAMS) $(SECURITY_PROGRAMS)

.PHONY: all clean security_tests

all: $(ALL_PROGRAMS)

security_tests: $(SECURITY_PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ -pthread

clean:
	rm -f $(ALL_PROGRAMS)

