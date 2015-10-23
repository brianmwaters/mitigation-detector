#ifndef _UTIL_H
#define _UTIL_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdnoreturn.h>

#ifndef NDEBUG
#define DEBUG(fmt, ...) { fprintf(stderr, "DEBUG: " fmt "\n", ## __VA_ARGS__); }
#else
#define DEBUG(fmt, ...) {}
#endif

noreturn void fail(const char *msg, int err);

#endif
