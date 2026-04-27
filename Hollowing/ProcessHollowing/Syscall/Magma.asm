;taken from Hell's Hall

.data
    PUBLIC g_SyscallNumber
    PUBLIC g_SyscallAddress
    
    g_SyscallNumber DWORD 0
    g_SyscallAddress QWORD 0

.code
PUBLIC SetConfig

SetConfig PROC
    mov g_SyscallNumber, ecx
    mov g_SyscallAddress, rdx
    ret
SetConfig ENDP

PUBLIC SyscallInvoker

SyscallInvoker PROC
    mov r10, rcx
    mov eax, g_SyscallNumber
    jmp qword ptr [g_SyscallAddress]
SyscallInvoker ENDP
end