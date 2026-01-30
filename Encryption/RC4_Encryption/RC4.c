#include "box.h"

BYTE _key[] = { 0xDE, 0xAD, 0xBE, 0xEF };

BOOL Rc4Encrypt
(
	IN PBYTE Shellcode,
	IN SIZE_T SizeOfShellcode
)
{

	NTSTATUS		STATUS = NULL;

	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof(key);

	data.Buffer = (PUCHAR)Shellcode;
	data.Length = SizeOfShellcode;

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&data, &key)) != 0x0)
	{
		PRINT_ERROR("SystemFunction033");
		return FALSE;
	}

	for (int i = 0; i < data.Length; i++)
	{
		if (i % 16 == 0)
		{
			printf("\n ");
		}
		printf(" %02x", data.Buffer[i]);
	}
	puts("\n");

	return TRUE;
}

BOOL Rc4Decrypt
(
	IN PBYTE Shellcode,
	IN SIZE_T SizeOfShellcode
)
{

	NTSTATUS		STATUS = NULL;

	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof(key);

	data.Buffer = (PUCHAR)Shellcode;
	data.Length = SizeOfShellcode;

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&data, &key)) != 0x0)
	{
		PRINT_ERROR("SystemFunction033");
		return FALSE;
	}

	for (int i = 0; i < data.Length; i++)
	{
		if (i % 16 == 0)
		{
			printf("\n ");
		}
		printf(" %02x", data.Buffer[i]);
	}
	puts("\n");

	return TRUE;

}