#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include "detect.h"
#include "util.h"

static struct {
    bool opt_rng_seed;
    unsigned int arg_rng_seed;
} opts;

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s: [-r seed]\n", name);
    exit(2);
}

static unsigned int str_to_uint(const char *str, int *err)
{
    long long num;
    char *end = NULL;

    if (isspace(str[0])) {
        *err = EINVAL;
        return 0;
    }
    // We use the signed version of strtoll to avoid silent negation of negative
    // inputs (see strtoll(3)). This restricts our input to values less than
    // LLONG_MAX, which may or may not be less than UINT_MAX. In practice, this
    // means the user may be unable to set the most significant bit of the seed
    // on platforms where sizeof (unsigned int) == sizeof (long long).
    errno = 0;
    num = strtoll(str, &end, 10);
    if (errno != 0) {
        *err = errno;
        return 0;
    } else if (end == str || *end != '\0') {
        *err = EINVAL;
        return 0;
    } else if (num < 0 || num > UINT_MAX) {
        *err = ERANGE;
        return 0;
    }
    *err = 0;
    return (unsigned int) num;
}

static void get_opts(int argc, char **argv)
{
    int opt;
    int err;

    opts.opt_rng_seed = false;
    opterr = 0; // suppress getopt error messages. see getopt(3)
    while ((opt = getopt(argc, argv, "r:")) != -1) {
        switch ((char) opt) {
        case 'r':
            opts.opt_rng_seed = true;
            opts.arg_rng_seed = str_to_uint(optarg, &err);
            if (err != 0) {
                usage(argv[0]);
            }
            break;
        default:
            usage(argv[0]);
        }
    }
    if (optind != argc) {
        usage(argv[0]);
    }
}

int main(int argc, char **argv)
{
    bool result;

    get_opts(argc, argv);
    result = detect_all(opts.opt_rng_seed ? &opts.arg_rng_seed : NULL, stdout);
    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
