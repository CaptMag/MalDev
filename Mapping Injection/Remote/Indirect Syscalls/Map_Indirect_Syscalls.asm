.data
extern g_NtOpenProcessSSN:DWORD
extern fn_NtCreateThreadExSSN:DWORD
extern fn_NtCreateSectionSSN:DWORD
extern fn_NtMapViewOfSectionSSN:DWORD
extern fn_NtQuerySystemInformationSSN:DWORD

extern g_NtOpenProcessSyscall:QWORD
extern fn_NtCreateThreadExSyscall:QWORD
extern fn_NtCreateSectionSyscall:QWORD
extern fn_NtMapViewOfSectionSyscall:QWORD
extern fn_NtQuerySystemInformationSyscall:QWORD

.code
NtOpenProcess proc
		mov r10, rcx
		mov eax, g_NtOpenProcessSSN       
		jmp qword ptr [g_NtOpenProcessSyscall]                       
		ret                             
NtOpenProcess endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, fn_NtCreateThreadExSSN
		jmp qword ptr fn_NtCreateThreadExSyscall
		ret
NtCreateThreadEx endp

NtMapViewOfSection proc
		mov r10, rcx
		mov eax, fn_NtMapViewOfSectionSSN
		jmp qword ptr fn_NtMapViewOfSectionSyscall
		ret
NtMapViewOfSection endp

NtCreateSection proc
		mov r10, rcx
		mov eax, fn_NtCreateSectionSSN
		jmp qword ptr fn_NtCreateSectionSyscall
		ret
NtCreateSection endp

NtQuerySystemInformation proc
		mov r10, rcx
		mov eax, fn_NtQuerySystemInformationSSN
		jmp qword ptr fn_NtQuerySystemInformationSyscall
		ret
NtQuerySystemInformation endp
end