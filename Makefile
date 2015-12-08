SH = /bin/sh

.PREFIX:
.PREFIX: .o .c

CC = clang
CFLAGS = -std=gnu99 -Wall -Wextra -O3 -fPIC
LDFLAGS = -Wl,-z,noexecstack -Wl,-rpath=. -ldl

TARGETS = mitigation-detector libdetect.so

.PHONY: all
all : $(TARGETS)

mitigation-detector : main.o detect.o libdetect.so
	$(CC) $(LDFLAGS) $^ -o $@

libdetect.so : detect.o
	$(CC) -shared $(LDFLAGS) -Wl,-soname,$@ $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean :
	rm -rf $(TARGETS) *.o *.core core
