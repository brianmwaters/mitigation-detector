SH = /bin/sh

.PREFIX:
.PREFIX: .o .c

CC = clang
CFLAGS = -std=gnu99 -Wall -Wextra -O3 -fPIE
LDFLAGS = -Wl,-z,noexecstack, -Wl,-rpath=. -ldl

TARGETS = mitigation-detector shared.so

.PHONY: all
all : $(TARGETS)

mitigation-detector : main.o detect.o shared.so
	$(CC) $(LDFLAGS) $^ -o $@

shared.so : shared.o
	$(CC) -shared $(LDFLAGS) -Wl,-soname,$@ $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean :
	rm -rf $(TARGETS) *.o *.core core
