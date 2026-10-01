#include "NtdllUnhooking.h"

// References:
// https://github.com/SaadAhla/ntdlll-unhooking-collection
// https://github.com/tlsbollei/HookDetector

int main(void)
{

	PVOID NtProtectVirtualMemoryAddress = NULL;

	if ((NtProtectVirtualMemoryAddress = GetProcAddress(GetModuleHandleW(L"Ntdll.dll"), "NtProtectVirtualMemory")) == NULL)
	{
		PRINT_ERROR("GetProcAddress");
		return 1;
	}

	INFO("Checking If NtApi is Hooked...");
	CheckForHookedNtApi(NtProtectVirtualMemoryAddress);

	OKAY("Done!");

	CHAR("Quit...");
	getchar();

	return 0;

}