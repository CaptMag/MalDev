; https://github.com/Maldev-Academy/HellHall/tree/main

default rel

section .data 
	NtdllSSN dd 0
	NtdllSyscall dq 0

section .text
	global InitializeSyscalls
	global ExecuteIndirect

InitializeSyscalls:
	mov [NtdllSSN], ecx
	mov [NtdllSyscall], rdx
	ret

ExecuteIndirect:
	mov r10, rcx
	mov eax, [NtdllSSN]
	jmp qword [NtdllSyscall]
	ret