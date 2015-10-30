.global shellcode_data
.global shellcode_size

.data
shellcode_data:
	mov	%edi, %eax
	add	%esi, %eax
	ret

	_shellcode_size = . - shellcode_data

.align 8
shellcode_size:
	.quad _shellcode_size
