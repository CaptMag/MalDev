#include "box.h"

int main()
{

	PVOID NtdllBuf = NULL;
	PVOID HookedNtdllTxt, UnhookedNtdllTxt = NULL;
	SIZE_T NtdllTxtSize = NULL;

	HMODULE NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NtdllHandle == NULL)
	{
		PRINT_ERROR("GetModuleHandleW");
		return 1;
	}

	if (!ReadTargetFile(&NtdllBuf))
	{
		PRINT_ERROR("ReadNtdll");
		return 1;
	}

	OKAY("Successfully Read Ntdll!");

	INFO("Comparing PE Headers...");

	CheckHeaders(NtdllBuf, NtdllHandle, &HookedNtdllTxt, &UnhookedNtdllTxt, &NtdllTxtSize);

	OKAY("Success");

	CHAR("Quit");
	getchar();

	return 0;

}