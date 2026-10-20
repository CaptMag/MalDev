#include <Windows.h>
#include <stdio.h>

DWORD djb2W(const char* str, SIZE_T length)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = str;

	do
	{
		UCHAR Char = *Ptr;

		if (!length)
		{
			if (!*Ptr)
				break;
		}
		else
		{
			if ((ULONG)(Ptr - (PUCHAR)str) >= length)
				break;

			if (!*Ptr)
				Ptr++;
		}

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	return hash;
}

DWORD djb2A(const char* str)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = str;

	do
	{

		UCHAR Char = *Ptr;

		if (!*Ptr) break;

		if (!*Ptr)
			Ptr++;

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	return hash;
}

DWORD djb2(const char* str)
{
	DWORD hash = 5381;
	CHAR c;

	while ((c = *str++))
	{
		hash = ((hash << 5) + hash) + c;
	}

	return hash;
}

int main()
{


	CONST CHAR* g_cAPINames[] = {
	"NtAllocateVirtualMemory",
	"NtProtectVirtualMemory",
	"NtFlushInstructionCache",
	"LdrGetProcedureAddress",
	"LdrLoadDll",
	"RtlMultiByteToUnicodeN",
	NULL
	};

	for (int i = 0; g_cAPINames[i] != NULL; i++)
		printf("#define \t %s_%s \t 0x%0.8X\n", g_cAPINames[i], "HASH", djb2A(g_cAPINames[i]));

	printf("#define %s - 0x%0.8X \n", "ntdll.dll", djb2W(L"ntdll.dll", wcslen(L"ntdll.dll") * sizeof(WCHAR)));


	return 0;

}