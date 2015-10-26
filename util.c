#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

void fail(const char *msg, int err)
{
    char *err_msg;

    if (err != 0) {
        err_msg = strerror(err);
    } else {
        err_msg = "Unknown error";
    }
    fprintf(stderr, "%s: %s\n", msg, err_msg);
    exit(EXIT_FAILURE);
}
