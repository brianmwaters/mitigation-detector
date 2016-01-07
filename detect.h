#ifndef _DETECT_H
#define _DETECT_H

#include <stdbool.h>

void setup_detections(unsigned int *rng_seed);
void teardown_detections(void);

bool detect_exec_prevent(const char *shellcode);
bool detect_mprotect_restrict(const char *shellcode);

bool test_stack(bool detect(const char *));
bool test_heap(bool detect(const char *));
bool test_data(bool detect(const char *));
bool test_bss(bool detect(const char *));
bool test_shlib_data(bool detect(const char *));
bool test_shlib_bss(bool detect(const char *));
bool test_mmap(bool detect(const char *));

#endif
