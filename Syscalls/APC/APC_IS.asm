.data 
extern fn_NtAllocateVirtualMemorySSN:DWORD
extern fn_NtWriteVirtualMemorySSN:DWORD
extern fn_NtProtectVirtualMemorySSN:DWORD
extern fn_NtFreeVirtualMemorySSN:DWORD
extern fn_NtQueueApcThreadSSN:DWORD


extern fn_NtAllocateVirtualMemorySyscall:QWORD
extern fn_NtWriteVirtualMemorySyscall:QWORD
extern fn_NtProtectVirtualMemorySyscall:QWORD
extern fn_NtFreeVirtualMemorySyscall:QWORD
extern fn_NtQueueApcThreadSyscall:QWORD


.code
NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtAllocateVirtualMemorySSN      
		jmp qword ptr [fn_NtAllocateVirtualMemorySyscall]                     
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtWriteVirtualMemorySSN      
		jmp qword ptr [fn_NtWriteVirtualMemorySyscall]                     
		ret                             
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtProtectVirtualMemorySSN       
		jmp qword ptr [fn_NtProtectVirtualMemorySyscall]                      
		ret                             
NtProtectVirtualMemory endp

NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, fn_NtFreeVirtualMemorySSN      
		jmp qword ptr [fn_NtFreeVirtualMemorySyscall]                  
		ret                             
NtFreeVirtualMemory endp

NtQueueApcThread proc
		mov r10, rcx
		mov eax, fn_NtQueueApcThreadSSN
		jmp qword ptr fn_NtQueueApcThreadSyscall
		ret
NtQueueApcThread endp
end