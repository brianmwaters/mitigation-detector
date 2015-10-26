#ifndef _UTIL_H
#define _UTIL_H

#include <stdlib.h>

#ifndef NDEBUG
#define DEBUG(fmt, ...) { fprintf(stderr, "DEBUG: " fmt "\n", ## __VA_ARGS__); }
#else
#define DEBUG(fmt, ...) {}
#endif

typedef enum {
    true = 1,
    false = 0
} bool;

void fail(const char *msg, int err);

#endif
