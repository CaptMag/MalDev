.code

getPeb PROC
		mov rax, gs:[60h] ; PEB
		ret
getPeb endp

checkdebugger PROC
		call getPeb ; calls PEB

		movzx   eax, byte ptr [rax+2] ; Checks the PEB offset at 0x2
		test eax, eax ; checks if value is 0
		jne debugger_found ; jump to debugger_found

		xor eax, eax ; EAX --> 0
		ret ; no debugger found

debugger_found:
		; Debugger found
		ret
checkdebugger endp

checkflag PROC
		call getPeb

		mov al, [rax + 0BCh] ; al at offset 0xBC, NtGlobalFlag
		and al, 70h
		cmp al, 70h
		jz debugger_found

		xor eax, eax ; no debugger present
		ret

debugger_found:
		mov eax, 1 ; debugger present
		ret
checkflag endp
end
