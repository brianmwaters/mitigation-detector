#ifndef _SHELLCODE_H
#define _SHELLCODE_H

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

#endif
