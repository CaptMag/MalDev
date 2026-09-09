; https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm

default rel

section .data
    NtdllSSN dd 0

section .text
    global GrabSSN
    global ExecuteDirect

GrabSSN:
    mov [NtdllSSN], 0
    mov [NtdllSSN], ecx
    ret

ExecuteDirect:
    mov r10, rcx
    mov eax, [NtdllSSN]
    syscall
    ret