#ifndef _DETECT_H
#define _DETECT_H

#include <stdbool.h>

bool detect_stack_exec_prevent(void);

bool detect_heap_exec_prevent(void);

bool detect_data_exec_prevent(void);

#endif
