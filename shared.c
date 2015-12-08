#include "shellcode.h"

// TODO: Compilers aren't guaranteed to Do What You Mean here
char shellcode_data_dlopen[SHELLCODE_SIZE] = SHELLCODE;
char shellcode_bss_dlopen[SHELLCODE_SIZE];
