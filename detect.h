#ifndef _DETECT_H
#define _DETECT_H

#include <stdbool.h>
#include <stddef.h>

void setup_detections(unsigned int *rng_seed);

bool detect_stack_exec_prevent(void);

bool detect_heap_exec_prevent(void);

bool detect_data_exec_prevent(void);

bool detect_bss_exec_prevent(void);

bool detect_stack_mprotect_restrict(void);

bool detect_heap_mprotect_restrict(void);

bool detect_data_mprotect_restrict(void);

bool detect_bss_mprotect_restrict(void);

#endif
