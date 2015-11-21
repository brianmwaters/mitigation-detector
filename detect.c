#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/wait.h>
#include <unistd.h>

#include "shellcode.h"
#include "util.h"

#include "detect.h"

static bool call_shellcode(const char *shellcode)
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
        asm("push %[op_a]\n\t"
            "push %[op_b]\n\t"
            "mov %[shellcode], %%eax\n\t"
            "call *%%eax\n\t"
            "add $8, %%esp\n\t"
            "mov %%eax, %[result]"
            : [result] "=rm" (result)
            : [op_a] "%rm" (op_a),
              [op_b] "r" (op_b),
              [shellcode] "r" (shellcode)
            : "eax");
#elif defined __GNUC__ && defined __amd64__
        asm("movl %[op_a], %%edi\n\t"
            "movl %[op_b], %%esi\n\t"
            "movq %[shellcode], %%rax\n\t"
            "call *%%rax\n\t"
            "movl %%eax, %[result]"
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

static bool execute_stack(void)
{
        char shellcode_stack[shellcode_size];

        DEBUG("Testing non-executable stack");
        memcpy(shellcode_stack, shellcode_data, shellcode_size);
        return call_shellcode(shellcode_stack);
}

static bool execute_heap(void)
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
        result = call_shellcode(shellcode_heap);
        free(shellcode_heap);
        return result;
}

static bool execute_data(void)
{
        DEBUG("Testing non-executable .data segment");
        return call_shellcode(shellcode_data);
}

static bool fork_and_test(bool (*test)(void))
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
                if (test()) {
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
        return fork_and_test(execute_stack);
}

bool detect_heap_exec_prevent(void)
{
        return fork_and_test(execute_heap);
}

bool detect_data_exec_prevent(void)
{
        return fork_and_test(execute_data);
}
