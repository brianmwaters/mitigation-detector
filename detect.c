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
static void *libdetect_handle;

// TODO: Compilers aren't guaranteed to Do What You Mean here
static char shellcode_data[SHELLCODE_SIZE] = SHELLCODE;
static char shellcode_bss[SHELLCODE_SIZE];
char shellcode_data_dlopen[SHELLCODE_SIZE] = SHELLCODE;
char shellcode_bss_dlopen[SHELLCODE_SIZE];

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

static void *get_libdetect_handle(void)
{
    void *libdetect_handle;

    // causes odr violation
    libdetect_handle = dlopen("./libdetect.so", RTLD_LAZY);
    if (libdetect_handle == NULL) {
        fprintf(stderr, "Error opening shared library: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return libdetect_handle;
}

void setup_detections(unsigned int *rng_seed)
{
    seed_rng(rng_seed);
    pagesize = get_pagesize();
    libdetect_handle = get_libdetect_handle();
}

void teardown_detections(void)
{
    int ret;

    ret = dlclose(libdetect_handle);
    if (ret != 0) {
        fprintf(stderr, "Error closing shared library: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

static bool fork_and_test(bool detect(const char *), const char *shellcode)
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
        if (detect(shellcode)) {
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_FAILURE);
        }
    } else {
        perror("Error spawning child process");
        exit(EXIT_FAILURE);
    }
}

bool detect_exec_prevent(const char *shellcode)
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
        : [result] "=rm" (result)
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

bool detect_mprotect_restrict(const char *shellcode)
{
    size_t size = SHELLCODE_SIZE;
    void *page;
    int ret;

    page = (void *) ((size_t) shellcode & ~(pagesize - 1));
    ret = mprotect(page, ((void *)shellcode - page) + size,
            PROT_READ|PROT_WRITE|PROT_EXEC);
    if (ret == -1 && errno != EACCES) {
        perror("Error setting memory protection");
        exit(EXIT_FAILURE);
    }
    return ret != -1;
}

bool test_stack(bool detect(const char *))
{
    char shellcode_stack[SHELLCODE_SIZE];

    memcpy(shellcode_stack, SHELLCODE, SHELLCODE_SIZE);
    return fork_and_test(detect, shellcode_stack);
}

bool test_heap(bool detect(const char *))
{
    char *shellcode_heap;
    bool result;

    shellcode_heap = malloc(SHELLCODE_SIZE);
    if (shellcode_heap == NULL) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memcpy(shellcode_heap, SHELLCODE, SHELLCODE_SIZE);
    result = fork_and_test(detect, shellcode_heap);
    free(shellcode_heap);
    return result;
}

bool test_data(bool detect(const char *))
{
    return fork_and_test(detect, shellcode_data);
}

bool test_bss(bool detect(const char *))
{
    memcpy(shellcode_bss, SHELLCODE, SHELLCODE_SIZE);
    return fork_and_test(detect, shellcode_bss);
}

bool test_shlib_data(bool detect(const char *))
{
    char *shellcode_data_dlopen;
    char *dlerror_ret;

    dlerror();
    shellcode_data_dlopen = dlsym(libdetect_handle, "shellcode_data_dlopen");
    dlerror_ret = dlerror();
    if (dlerror_ret != NULL) {
        fprintf(stderr, "Error loading symbol from shared library: %s\n",
                dlerror_ret);
        exit(EXIT_FAILURE);
    }
    return fork_and_test(detect, shellcode_data_dlopen);
}

bool test_shlib_bss(bool detect(const char *))
{
    char *shellcode_bss_dlopen;
    char *dlerror_ret;

    dlerror();
    shellcode_bss_dlopen = dlsym(libdetect_handle, "shellcode_bss_dlopen");
    dlerror_ret = dlerror();
    if (dlerror_ret != NULL) {
        fprintf(stderr, "Error loading symbol from shared library: %s\n",
                dlerror_ret);
        exit(EXIT_FAILURE);
    }
    memcpy(shellcode_bss_dlopen, SHELLCODE, SHELLCODE_SIZE);
    return fork_and_test(detect, shellcode_bss_dlopen);
}

bool test_mmap(bool detect(const char *))
{
    char *shellcode_mmap;
    bool result;
    int ret;

    shellcode_mmap = mmap(NULL, SHELLCODE_SIZE, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (shellcode_mmap == MAP_FAILED) {
        perror("Error mapping memory");
        exit(EXIT_FAILURE);
    }
    memcpy(shellcode_mmap, SHELLCODE, SHELLCODE_SIZE);
    result = fork_and_test(detect, shellcode_mmap);
    ret = munmap(shellcode_mmap, SHELLCODE_SIZE);
    if (ret == -1) {
        perror("Error unmapping memory");
        exit(EXIT_FAILURE);
    }
    return result;
}
