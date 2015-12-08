#include "shellcode.h"

// TODO: Compilers aren't guaranteed to Do What You Mean here
char shellcode_data_shared[SHELLCODE_SIZE] = SHELLCODE;
char shellcode_bss_shared[SHELLCODE_SIZE];
