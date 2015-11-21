#ifndef _UTIL_H
#define _UTIL_H

#include <stdlib.h>

// TODO: This use of ## w/ , is GCC-specific
#ifndef NDEBUG
#define DEBUG(fmt, ...) { fprintf(stderr, "DEBUG: " fmt "\n", ## __VA_ARGS__); }
#else
#define DEBUG(fmt, ...) {}
#endif

void fail(const char *msg, int err);

#endif
