#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shellcode.h"

#include "detect.h"

static size_t pagesize;

// TODO: Compilers aren't guaranteed to Do What You Mean here
static char shellcode_data[SHELLCODE_SIZE] = SHELLCODE;
static char shellcode_bss[SHELLCODE_SIZE];

static size_t get_pagesize(void)
{
    long sc_ret;

    sc_ret = sysconf(_SC_PAGESIZE);
    if (sc_ret == -1) {
        perror("Error getting page size");
        exit(EXIT_FAILURE);
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
            fprintf(stderr, "Error getting current time");
            exit(EXIT_FAILURE);
        }
        seed = (unsigned int) cur;
    }
    srand(seed);
}

// run this before running any detections
static void setup_globals(unsigned int *rng_seed)
{
    pagesize = get_pagesize();
    seed_rng(rng_seed);
}

static bool test_exec(const void *shellcode)
{
    uint32_t op_a, op_b;
    uint32_t sum; // the expected sum
    uint32_t result; // the actual sum

    op_a = (uint32_t) rand();
    op_b = (uint32_t) rand();
    sum = op_a + op_b;
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
        perror("Error setting memory protection");
        exit(EXIT_FAILURE);
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
        perror("Error flusing stdout");
        exit(EXIT_FAILURE);
    }
    err = fflush(stderr);
    if (err != 0) {
        perror("Error flusing stderr");
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

static bool detect(const char *msg, bool test(const void *), const void *data)
{
    bool result;
    int ret;

    result = fork_and_test(test, data);
    ret = printf("%s: %s\n", result ? "PASS" : "VULN", msg);
    if (ret < 0) {
        perror("Error printing output");
        exit(EXIT_FAILURE);
    }
    return result;
}

bool detect_all(unsigned int *rng_seed)
{
    char shellcode_stack[SHELLCODE_SIZE];
    char *shellcode_heap;
    char *shellcode_mmap;
    char *shellcode_data_dlopen;
    char *shellcode_bss_dlopen;
    void *shared_handle;
    char *dlerror_ret;
   int ret;
    bool result;

    setup_globals(rng_seed);

    // set up the various shellcode buffers
    shellcode_heap = malloc(SHELLCODE_SIZE);
    if (shellcode_heap == NULL) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }
    shellcode_mmap = mmap(NULL, SHELLCODE_SIZE, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (shellcode_mmap == MAP_FAILED) {
        perror("Error mapping memory");
        exit(EXIT_FAILURE);
    }
    shared_handle = dlopen("./shared.so", RTLD_LAZY|RTLD_LOCAL);
    if (shared_handle == NULL) {
        fprintf(stderr, "Error opening shared library: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror();
    shellcode_data_dlopen = dlsym(shared_handle, "shellcode_data_dlopen");
    dlerror_ret = dlerror();
    if (dlerror_ret != NULL) {
        fprintf(stderr, "Error loading symbol from shared library: %s\n",
                dlerror_ret);
        exit(EXIT_FAILURE);
    }
    dlerror();
    shellcode_bss_dlopen = dlsym(shared_handle, "shellcode_bss_dlopen");
    dlerror_ret = dlerror();
    if (dlerror_ret != NULL) {
        fprintf(stderr, "Error loading symbol from shared library: %s\n",
                dlerror_ret);
        exit(EXIT_FAILURE);
    }
    memcpy(shellcode_stack, SHELLCODE, SHELLCODE_SIZE);
    memcpy(shellcode_heap, SHELLCODE, SHELLCODE_SIZE);
    memcpy(shellcode_bss, SHELLCODE, SHELLCODE_SIZE);
    memcpy(shellcode_bss_dlopen, SHELLCODE, SHELLCODE_SIZE);
    memcpy(shellcode_mmap, SHELLCODE, SHELLCODE_SIZE);

    // run the detections
    result = true;
    result &= detect("stack segment execution prevention",
            test_exec, shellcode_stack);
    result &= detect("heap segment execution prevention",
            test_exec, shellcode_heap);
    result &= detect("data segment execution prevention",
            test_exec, shellcode_data);
    result &= detect("bss segment execution prevention",
            test_exec, shellcode_bss);
    result &= detect("dlopen()'ed data segment execution prevention",
            test_exec, shellcode_data_dlopen);
    result &= detect("dlopen()'ed bss segment execution prevention",
            test_exec, shellcode_bss_dlopen);
    result &= detect("mmap()'ed segment execution prevention",
            test_exec, shellcode_mmap);
    result &= detect("stack segment mprotect() restrictions",
            test_mprotect, shellcode_stack);
    result &= detect("heap segment mprotect() restrictions",
            test_mprotect, shellcode_heap);
    result &= detect("data segment mprotect() restrictions",
            test_mprotect, shellcode_data);
    result &= detect("bss segment mprotect() restrictions",
            test_mprotect, shellcode_bss);
    result &= detect("dlopen()'ed data segment mprotect() restrictions",
            test_mprotect, shellcode_data_dlopen);
    result &= detect("dlopen()'ed bss segment mprotect() restrictions",
            test_mprotect, shellcode_bss_dlopen);
    result &= detect("mmap()'ed segment mprotect() restrictions",
            test_mprotect, shellcode_mmap);

    // tear down the various shellcode buffers
    free(shellcode_heap);
    ret = munmap(shellcode_mmap, SHELLCODE_SIZE);
    if (ret == -1) {
        perror("Error unmapping memory");
        exit(EXIT_FAILURE);
    }
    ret = dlclose(shared_handle);
    if (ret != 0) {
        fprintf(stderr, "Error closing shared library: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    // return the result
    return result;
}
