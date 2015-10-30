.global shellcode_master
.global shellcode_size

.data
shellcode_master:
	mov	%edi, %eax
	add	%esi, %eax
	ret

shellcode_master_end:

.align 8
shellcode_size:
	.int shellcode_master_end - shellcode_master
