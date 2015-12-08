#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "util.h"

#include "detect.h"

// Adds two 32-bit unsigned ints using the Linux calling convention for the
// architecture
#if defined __i386__
#define SHELLCODE "\x8b\x44\x24\x04\x03\x44\x24\x08\xc3"
#elif defined __amd64__
#define SHELLCODE "\x89\xf8\x01\xf0\xc3"
#else
#error platform not supported
#endif
#define SHELLCODE_SIZE (sizeof (SHELLCODE))

static size_t pagesize;

// TODO: Compilers aren't guaranteed to Do What You Mean here
static char shellcode_data[SHELLCODE_SIZE] = SHELLCODE;
static char shellcode_bss[SHELLCODE_SIZE];

static size_t get_pagesize(void)
{
    long sc_ret;

    sc_ret = sysconf(_SC_PAGESIZE);
    if (sc_ret == -1) {
        fail("Error getting page size", errno);
    }
    assert(sc_ret >= 0 && (unsigned long) sc_ret <= SIZE_MAX);
    return sc_ret;
}

static void seed_rng(unsigned int *arg)
{
    unsigned int seed;
    time_t cur;

    if (arg != NULL) {
        seed = *arg;
    } else {
        cur = time(NULL);
        if (cur == -1) {
            fail("Could not get current time", 0);
        }
        seed = (unsigned int) cur;
    }
    srand(seed);
}

// run this before running any detections
static void setup_detections(unsigned int *rng_seed)
{
    pagesize = get_pagesize();
    seed_rng(rng_seed);
}

static bool test_exec(const void *shellcode)
{
    uint32_t op_a, op_b;
    uint32_t sum; // the expected sum
    uint32_t result; // the actual sum

    op_a = (uint32_t)rand();
    op_b = (uint32_t)rand();
    DEBUG("op_a:\t%" PRIu32, op_a);
    DEBUG("op_b:\t%" PRIu32, op_b);
    sum = op_a + op_b;
    DEBUG("sum:\t%" PRIu32, sum);
#if defined __GNUC__ && defined __i386__
    asm("push   %[op_a]\n\t"
        "push   %[op_b]\n\t"
        "mov    %[shellcode], %%eax\n\t"
        "call   *%%eax\n\t"
        "add    $8, %%esp\n\t"
        "mov    %%eax, %[result]"
        : [result] "=rm" (result))
        : [op_a] "%rm" (op_a),
          [op_b] "r" (op_b),
          [shellcode] "r" (shellcode)
        : "eax");
#elif defined __GNUC__ && defined __amd64__
    asm("movl   %[op_a], %%edi\n\t"
        "movl   %[op_b], %%esi\n\t"
        "movq   %[shellcode], %%rax\n\t"
        "call   *%%rax\n\t"
        "movl   %%eax, %[result]"
        : [result] "=rm" (result)
        : [op_a] "%rm" (op_a),
          [op_b] "rm" (op_b),
          [shellcode] "rm" (shellcode)
        : "rax", "rdi", "rsi");
#else
#error platform not supported
#endif
    DEBUG("result:\t%" PRIu32, result);
    return result == sum;
}

static bool test_mprotect(const void *buf)
{
    size_t size = SHELLCODE_SIZE;
    void *page;
    int ret;

    page = (void *) ((size_t) buf & ~(pagesize - 1));
	ret = mprotect(page, (buf - page) + size, PROT_READ|PROT_WRITE|PROT_EXEC);
    if (ret == -1 && errno != EACCES) {
        fail("Error calling mprotect()", errno);
    }
    return ret != -1;
}

static bool fork_and_test(bool test(const void *), const void *data)
{
    bool executed; // whether the shellcode successfully executed
    pid_t fpid, wpid;
    int status;
    int err;

    err = fflush(stdout);
    if (err != 0) {
        fail("Error flushing stdout", errno);
    }
    err = fflush(stderr);
    if (err  != 0) {
        fail("Error flushing stderr", errno);
    }
    fpid = fork();
    if (fpid > 0) {
        wpid = wait(&status);
        if (wpid > 0) {
            executed = (status == EXIT_SUCCESS);
        } else if (wpid == -1 && errno == EINTR) {
            executed = false;
        } else {
            fail("Error waiting for child process", errno);
        }
        return !executed;
    } else if (fpid == 0) {
        if (test(data)) {
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_FAILURE);
        }
    } else {
        fail("Error spawning child process", errno);
    }
}

static bool detect(bool test(const void *), const void *data,
        FILE *outfile, const char *message)
{
    bool result;
    int ret;

    result = fork_and_test(test, data);
    ret = fprintf(outfile, "%s: %s\n", result ? "PASS" : "VULN", message);
    if (ret < 0) {
        fail("Error printing to output file", errno);
    }
    return result;
}

bool detect_all(unsigned int *rng_seed, FILE *outfile)
{
    char shellcode_stack[SHELLCODE_SIZE];
    char *shellcode_heap;
    char *shellcode_mmap;
    bool result;
    int ret;

    // initialize stuff
    setup_detections(rng_seed);
    // set up the various shellcode buffers
    shellcode_heap = malloc(SHELLCODE_SIZE);
    if (shellcode_heap == NULL) {
        fail("Error allocating memory", errno);
    }
    shellcode_mmap = mmap(NULL, SHELLCODE_SIZE, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (shellcode_mmap == MAP_FAILED) {
        fail("Error mapping memory", errno);
    }
    memcpy(shellcode_stack, shellcode_data, SHELLCODE_SIZE);
    memcpy(shellcode_heap, shellcode_data, SHELLCODE_SIZE);
    memcpy(shellcode_bss, shellcode_data, SHELLCODE_SIZE);
    memcpy(shellcode_mmap, shellcode_data, SHELLCODE_SIZE);
    // run the detections
    result = true;
    result &= detect(test_exec, shellcode_stack, outfile, "Stack segment execution prevention");
    result &= detect(test_exec, shellcode_heap, outfile, "Heap segment execution prevention");
    result &= detect(test_exec, shellcode_data, outfile, "Data segment execution prevention");
    result &= detect(test_exec, shellcode_bss, outfile, "BSS segment execution prevention");
    result &= detect(test_exec, shellcode_mmap, outfile, "Mapped memory execution prevention");
    result &= detect(test_mprotect, shellcode_stack, outfile, "Stack segment mprotect() restrictions");
    result &= detect(test_mprotect, shellcode_heap, outfile, "Heap segment mprotect() restrictions");
    result &= detect(test_mprotect, shellcode_data, outfile, "Data segment mprotect() restrictions");
    result &= detect(test_mprotect, shellcode_bss, outfile, "BSS segment mprotect() restrictions");
    result &= detect(test_mprotect, shellcode_mmap, outfile, "Mapped memory mprotect() restrictions");
    // tear down the various shellcode buffers
    free(shellcode_heap);
    ret = munmap(shellcode_mmap, SHELLCODE_SIZE);
    if (ret == -1) {
        fail("Error unmapping page", errno);
    }
    // return the result
    return result;
}
