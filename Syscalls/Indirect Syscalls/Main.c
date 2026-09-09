#include "Syscalls.h"

int main()
{

	CHAR Shellcode[] = "\x90\x90\x90\x90\xcc\xcc\xcc\xcc\xc3";
	SIZE_T PayloadSize = sizeof(Shellcode);

	ExecuteIndirectSyscalls(PayloadSize);

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}