.data
extern fn_NtAllocateVirtualMemorySSN:DWORD
extern fn_NtWriteVirtualMemorySSN:DWORD
extern fn_NtProtectVirtualMemorySSN:DWORD
extern fn_NtWaitForSingleObjectSSN:DWORD
extern fn_NtGetContextThreadSSN:DWORD
extern fn_NtSetContextThreadSSN:DWORD
extern fn_NtResumeThreadSSN:DWORD
extern fn_NtCreateFileSSN:DWORD
extern fn_NtReadFileSSN:DWORD
extern fn_NtQueryInformationFileSSN:DWORD

extern fn_NtAllocateVirtualMemorySyscall:QWORD
extern fn_NtWriteVirtualMemorySyscall:QWORD
extern fn_NtProtectVirtualMemorySyscall:QWORD
extern fn_NtWaitForSingleObjectSyscall:QWORD
extern fn_NtGetContextThreadSyscall:QWORD
extern fn_NtSetContextThreadSyscall:QWORD
extern fn_NtResumeThreadSyscall:QWORD
extern fn_NtCreateFileSyscall:QWORD
extern fn_NtReadFileSyscall:QWORD
extern fn_NtQueryInformationFileSyscall:QWORD

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

NtCreateFile proc
		mov r10, rcx
		mov eax, fn_NtCreateFileSSN
		jmp qword ptr fn_NtCreateFileSyscall
		ret
NtCreateFile endp

NtReadFile proc
		mov r10, rcx
		mov eax, fn_NtReadFileSSN
		jmp qword ptr fn_NtReadFileSyscall
		ret
NtReadFile endp

NtQueryInformationFile proc
		mov r10, rcx
		mov eax, fn_NtQueryInformationFileSSN
		jmp qword ptr fn_NtQueryInformationFileSyscall
		ret
NtQueryInformationFile endp
end