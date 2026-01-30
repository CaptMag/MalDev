#include "box.h"

BOOL XorEncrypt
(
	IN PBYTE Shellcode,
	IN SIZE_T SizeOfShellcode,
	IN CHAR Key
)
{

	for (size_t i = 0; i < SizeOfShellcode; i++)
	{
		Shellcode[i] = Shellcode[i] ^ (Key + i);
		if (i % 16 == 0)
		{
			printf("\n ");
		}
		printf(" %02x", Shellcode[i]);
	}
	puts("\n");

	return TRUE;

}

BOOL XorDecrypt
(
	IN PBYTE Shellcode,
	IN SIZE_T SizeOfShellcode,
	IN CHAR Key
)
{

	for (size_t i = 0; i < SizeOfShellcode; i++)
	{
		Shellcode[i] = Shellcode[i] ^ (Key + i);
		if (i % 16 == 0)
		{
			printf("\n ");
		}
		printf(" %02x", Shellcode[i]);
	}
	puts("\n");

	return TRUE;

}