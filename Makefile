SH = /bin/sh

.PREFIX:
.PREFIX: .o .c

CC = clang
CFLAGS = -std=gnu99 -DNDEBUG -Wall -Wextra -O3
LDFLAGS = -Wl,-z,noexecstack

TARGETS = mitigation-detector

.PHONY: all
all : $(TARGETS)

mitigation-detector : main.o detect.o util.o
	$(CC) $(LDFLAGS) $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean :
	rm -rf $(TARGETS) *.o *.core core
