#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <time.h>

#include <unistd.h>

#include "detect.h"
#include "util.h"

static struct {
    unsigned int opts;
    uint32_t rng_seed;
} args;

#define OPT_RNG_SEED                0x01
#define OPT_TEST_STACK_EXEC_PREVENT 0x02
#define OPT_TEST_HEAP_EXEC_PREVENT  0x04
#define OPT_TEST_DATA_EXEC_PREVENT  0x08

#define OPTS_NONE 0x00
#define OPTS_TEST_ALL (OPT_TEST_STACK_EXEC_PREVENT | \
                       OPT_TEST_HEAP_EXEC_PREVENT | \
                       OPT_TEST_DATA_EXEC_PREVENT)

static noreturn void usage(const char *name)
{
    fprintf(stderr, "Usage: %s: [-r seed] [-s] [-h] [-d]\n", name);
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
    *err = 0;
    assert(num > 0);
    assert(num <= UINT_MAX);
    return (unsigned int) num;
}

static void get_args(int argc, char **argv)
{
    int opt;
    int err;

    args.opts = 0;
    opterr = 0; // suppress getopt error messages. see getopt(3)
    while ((opt = getopt(argc, argv, "r:shd")) != -1) {
        switch ((char) opt) {
        case 'r':
            args.opts |= OPT_RNG_SEED;
            args.rng_seed = str_to_uint(optarg, &err);
            if (err != 0) {
                usage(argv[0]);
            }
            break;
        case 's':
            args.opts |= OPT_TEST_STACK_EXEC_PREVENT;
            break;
        case 'h':
            args.opts |= OPT_TEST_HEAP_EXEC_PREVENT;
            break;
        case 'd':
            args.opts |= OPT_TEST_DATA_EXEC_PREVENT;
            break;
        default:
            usage(argv[0]);
        }
    }
    // if no tests are specified, assume we want all of them
    if ((args.opts & OPTS_TEST_ALL) == OPTS_NONE) {
        args.opts |= OPTS_TEST_ALL;
    }
    if (optind != argc) {
        usage(argv[0]);
    }
    assert(args.opts &= OPTS_TEST_ALL);
}

static void seed_rng(void)
{
    unsigned int seed;
    time_t cur;

    if (args.opts & OPT_RNG_SEED) {
        seed = args.rng_seed;
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

    if (args.opts & OPT_TEST_STACK_EXEC_PREVENT) {
        result &= detect_and_display(detect_stack_exec_prevent,
                "Stack segment execution prevention");
    }
    if (args.opts & OPT_TEST_HEAP_EXEC_PREVENT) {
        result &= detect_and_display(detect_heap_exec_prevent,
                "Heap segment execution prevention");
    }
    if (args.opts & OPT_TEST_DATA_EXEC_PREVENT) {
        result &= detect_and_display(detect_data_exec_prevent,
                "Data segment execution prevention");
    }
    return result;
}

int main(int argc, char **argv)
{
    bool result;

    get_args(argc, argv);
    seed_rng();
    result = detect_mitigations();
    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
