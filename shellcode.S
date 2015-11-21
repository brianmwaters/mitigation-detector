.global shellcode_data
.global shellcode_size

#if defined __i386__

.data
shellcode_data:
	mov	0x4(%esp), %eax
	add     0x8(%esp), %eax
	ret

	_shellcode_size = . - shellcode_data

.align 4
shellcode_size:
	.long _shellcode_size

#elif defined __amd64__

.data
shellcode_data:
	mov	%edi, %eax
	add	%esi, %eax
	ret

	_shellcode_size = . - shellcode_data

.align 8
shellcode_size:
	.quad _shellcode_size

#endif
