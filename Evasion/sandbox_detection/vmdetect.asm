.686
.model flat, c
option casemap:none

.code

leaf00 PROC pOut:PTR DWORD
		push ebx
		push esi

		mov esi, pOut

		xor eax, eax ; set EAX = 0
		cpuid

		mov [esi], eax
		mov [esi+4], ebx
		mov [esi+8], ecx
		mov [esi+12], edx

		pop esi
		pop ebx
		ret
leaf00 ENDP

leaf01 PROC pOut:ptr dword
		push ebx
		push esi

		mov esi, pOut

		mov eax, 1
		cpuid
		
		mov [esi], eax ; info for EAX
		mov [esi + 4], ebx ; info for EBX
		mov [esi + 8], ecx ; info for ECX
		mov [esi + 12], edx ; info for EDX

		pop esi
		pop ebx
		ret
leaf01 endp

leaf02 PROC pOut:ptr dword
		push ebx
		push esi

		mov esi, pOut

		mov eax, 80000002h
		cpuid

		mov [esi], eax
		mov [esi + 4], ebx
		mov [esi + 8], ecx
		mov [esi + 12], edx

		mov eax, 80000003h
		cpuid

		mov [esi + 16], eax
		mov [esi + 20], ebx
		mov [esi + 24], ecx
		mov [esi + 28], edx

		mov eax, 80000004h
		cpuid

		mov [esi + 32], eax
		mov [esi + 36], ebx
		mov [esi + 40], ecx
		mov [esi + 44], edx

		mov byte ptr [esi + 48], 0

		pop esi
		pop ebx
		ret
leaf02 endp

leaf04 proc pOut:ptr dword
		push ebx
		push esi

		mov esi, pOut

		mov eax, 40000000h ; Used for MS Hypervisor
		cpuid

		mov [esi], eax
		mov [esi + 4], ebx
		mov [esi + 8], ecx
		mov [esi + 12], edx

		pop esi
		pop ebx
		ret
leaf04 endp
end