#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const size_t shellcode_size = sizeof (SHELLCODE);

// Compilers aren't guaranteed to Do What You Mean here
static char shellcode_data[shellcode_size] = SHELLCODE;
static char shellcode_bss[shellcode_size];

static bool test_shellcode(const void *shellcode)
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

static bool fork_and_test(bool test(const void *), const void *data)
{
    bool executed; // whether the shellcode successfully executed
    pid_t fpid, wpid;
    int status;
    int err;

    err = fflush(stdout);
    if (err != 0) {
        perror("Error flushing stdout");
        exit(EXIT_FAILURE);
    }
    err = fflush(stderr);
    if (err != 0) {
        perror("Error flushing stderr");
        exit(EXIT_FAILURE);
    }
    fpid = fork();
    if (fpid > 0) {
        wpid = wait(&status);
        if (wpid > 0) {
            executed = (status == EXIT_SUCCESS);
        } else if (wpid == -1 && errno == EINTR) {
            executed = false;
        } else {
            perror("Error waiting for child process");
            exit(EXIT_FAILURE);
        }
        return !executed;
    } else if (fpid == 0) {
        if (test(data)) {
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_FAILURE);
        }
    } else {
        perror("Error spawning child process");
        exit(EXIT_FAILURE);
    }
}

bool detect_stack_exec_prevent(void)
{
    char shellcode_stack[shellcode_size];

    DEBUG("Testing non-executable stack");
    memcpy(shellcode_stack, shellcode_data, shellcode_size);
    return fork_and_test(test_shellcode, shellcode_stack);
}

bool detect_heap_exec_prevent(void)
{
    char *shellcode_heap;
    bool result;

    DEBUG("Testing non-executable heap");
    shellcode_heap = malloc(shellcode_size);
    if (shellcode_heap == NULL) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memcpy(shellcode_heap, shellcode_data, shellcode_size);
    result = fork_and_test(test_shellcode, shellcode_heap);
    free(shellcode_heap);
    return result;
}

bool detect_data_exec_prevent(void)
{
    DEBUG("Testing non-executable data segment");
    return fork_and_test(test_shellcode, shellcode_data);
}

bool detect_bss_exec_prevent(void)
{
    DEBUG("Testing non-executable BSS segment");
    memcpy(shellcode_bss, shellcode_data, shellcode_size);
    return fork_and_test(test_shellcode, shellcode_bss);
}
