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

// Adds two unsigned 32-bit ints using the Linux calling convention
#if defined __i386__
#define SHELLCODE "\x8b\x44\x24\x04\x03\x44\x24\x08\xc3"
#elif defined __amd64__
#define SHELLCODE "\x89\xf8\x01\xf0\xc3"
#else
#error platform not supported
#endif
#define SHELLCODE_SIZE (sizeof (SHELLCODE))

// TODO: Compilers aren't guaranteed to Do What You Mean here
static char shellcode_data[SHELLCODE_SIZE] = SHELLCODE;
static char shellcode_bss[SHELLCODE_SIZE];

static size_t pagesize;

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

static void get_pagesize(void)
{
    long sc_ret;

    sc_ret = sysconf(_SC_PAGESIZE);
    if (sc_ret == -1) {
        fail("Error getting page size", errno);
    }
    assert(sc_ret >= 0 && (unsigned long) sc_ret <= SIZE_MAX);
    pagesize = sc_ret;
}

// call this before running any detections
void setup_detections(unsigned int *rng_seed)
{
    seed_rng(rng_seed);
    get_pagesize();
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
    if (err != 0) {
        fail("Error flushing stderr", errno);
    }
    fpid = fork();
    if (fpid > 0) {
        wpid = wait(&status);
        if (wpid > 0) {
            executed = (status == EXIT_SUCCESS);
    memcpy(shellcode_bss, shellcode_data, SHELLCODE_SIZE);
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

bool detect_stack_exec_prevent(void)
{
    char shellcode_stack[SHELLCODE_SIZE];

    DEBUG("Testing non-executable stack");
    memcpy(shellcode_stack, shellcode_data, SHELLCODE_SIZE);
    return fork_and_test(test_exec, shellcode_stack);
}

bool detect_heap_exec_prevent(void)
{
    char *shellcode_heap;
    bool result;

    DEBUG("Testing non-executable heap");
    shellcode_heap = malloc(SHELLCODE_SIZE);
    if (shellcode_heap == NULL) {
        fail("Error allocating memory", errno);
    }
    memcpy(shellcode_heap, shellcode_data, SHELLCODE_SIZE);
    result = fork_and_test(test_exec, shellcode_heap);
    free(shellcode_heap);
    return result;
}

bool detect_data_exec_prevent(void)
{
    DEBUG("Testing non-executable data segment");
    memcpy(shellcode_bss, shellcode_data, SHELLCODE_SIZE);
    return fork_and_test(test_exec, shellcode_data);
}

bool detect_bss_exec_prevent(void)
{
    DEBUG("Testing non-executable BSS segment");
    memcpy(shellcode_bss, shellcode_data, SHELLCODE_SIZE);
    return fork_and_test(test_exec, shellcode_bss);
}

bool detect_stack_mprotect_restrict(void)
{
    char shellcode_stack[SHELLCODE_SIZE];

    DEBUG("Testing stack mprotect() restrictions");
    return fork_and_test(test_mprotect, shellcode_stack);
}

bool detect_heap_mprotect_restrict(void)
{
    char *shellcode_heap;
    bool result;

    DEBUG("Testing heap mprotect() restrictions");
    shellcode_heap = malloc(SHELLCODE_SIZE);
    if (shellcode_heap == NULL) {
        fail("Error allocating memory", errno);
    }
    result = fork_and_test(test_mprotect, shellcode_heap);
    free(shellcode_heap);
    return result;
}

bool detect_data_mprotect_restrict(void)
{
    DEBUG("Testing heap mprotect() restrictions");
    return fork_and_test(test_mprotect, shellcode_data);
}

bool detect_bss_mprotect_restrict(void)
{
    DEBUG("Testing heap mprotect() restrictions");
    return fork_and_test(test_mprotect, shellcode_bss);
}
