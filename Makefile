SH = /bin/sh

.PREFIX:
.PREFIX: .o .s .c

CC = clang
CFLAGS = -std=gnu11 -D_XOPEN_SOURCE=700 -DNDEBUG -Wall -Wextra -O3
LDFLAGS = -z noexecstack

TARGETS = mitigation-detector

.PHONY: all
all : $(TARGETS)

mitigation-detector : main.o detect.o shellcode.o util.o
	$(CC) $(LDFLAGS) $^ -o $@

%.o : %.s
	$(CC) -c $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean :
	rm -rf $(TARGETS) *.o
