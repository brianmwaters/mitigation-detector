#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

    errno = 0;
    num = strtoll(str, &end, 10);
    if (errno != 0 || *end != '\0' || *str == '\0' ||
            num < 0 || num > UINT_MAX) {
        *err = errno;
        return 0;
    }
    assert(num > 0);
    assert(num <= UINT_MAX);
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

static void seed_rng(void)
{
    unsigned int seed;
    time_t cur;

    if (opts.opt_rng_seed) {
        seed = opts.arg_rng_seed;
    } else {
        cur = time(NULL);
        if (cur == -1) {
            fail("Could not get current time", 0);
        }
        seed = (unsigned int) cur;
    }
    srand(seed);
}

static bool detect_and_display(bool (*test)(void), const char *name)
{
    bool result;
    int err;

    result = test();
    err = printf("%s: %s\n", result ? "PASS" : "FAIL", name);
    if (err < 0) {
        fail("Error printing to stdout", errno);
    }
    return result;
}

static bool detect_mitigations(void)
{
    bool result = true;

    result &= detect_and_display(detect_stack_exec_prevent,
        "Stack segment execution prevention");
    result &= detect_and_display(detect_heap_exec_prevent,
        "Heap segment execution prevention");
    result &= detect_and_display(detect_data_exec_prevent,
        "Data segment execution prevention");
    return result;
}

int main(int argc, char **argv)
{
    bool result;

    get_opts(argc, argv);
    seed_rng();
    result = detect_mitigations();
    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
