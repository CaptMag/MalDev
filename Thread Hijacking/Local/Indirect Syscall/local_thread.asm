.data
extern fn_NtAllocateVirtualMemorySSN:DWORD
extern fn_NtWriteVirtualMemorySSN:DWORD
extern fn_NtProtectVirtualMemorySSN:DWORD
extern fn_NtWaitForSingleObjectSSN:DWORD
extern g_NtCreateThreadExSSN:DWORD
extern fn_NtGetContextThreadSSN:DWORD
extern fn_NtSetContextThreadSSN:DWORD
extern fn_NtResumeThreadSSN:DWORD

extern fn_NtAllocateVirtualMemorySyscall:QWORD
extern fn_NtWriteVirtualMemorySyscall:QWORD
extern fn_NtProtectVirtualMemorySyscall:QWORD
extern fn_NtWaitForSingleObjectSyscall:QWORD
extern g_NtCreateThreadExSyscall:QWORD
extern fn_NtGetContextThreadSyscall:QWORD
extern fn_NtSetContextThreadSyscall:QWORD
extern fn_NtResumeThreadSyscall:QWORD

.code

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtAllocateVirtualMemorySSN
		jmp qword ptr fn_NtAllocateVirtualMemorySyscall
		ret
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtWriteVirtualMemorySSN
		jmp qword ptr fn_NtWriteVirtualMemorySyscall
		ret
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtProtectVirtualMemorySSN
		jmp qword ptr fn_NtProtectVirtualMemorySyscall
		ret
NtProtectVirtualMemory endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, fn_NtWaitForSingleObjectSSN
		jmp qword ptr fn_NtWaitForSingleObjectSyscall
		ret
NtWaitForSingleObject endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, g_NtCreateThreadExSSN      
		jmp qword ptr [g_NtCreateThreadExSyscall]                      
		ret                             
NtCreateThreadEx endp

NtGetContextThread proc
		mov r10, rcx
		mov eax, fn_NtGetContextThreadSSN
		jmp qword ptr fn_NtGetContextThreadSyscall
		ret
NtGetContextThread endp

NtSetContextThread proc
		mov r10, rcx
		mov eax, fn_NtSetContextThreadSSN
		jmp qword ptr fn_NtSetContextThreadSyscall
		ret
NtSetContextThread endp

NtResumeThread proc
		mov r10, rcx
		mov eax, fn_NtResumeThreadSSN
		jmp qword ptr fn_NtResumeThreadSyscall
		ret
NtResumeThread endp
end