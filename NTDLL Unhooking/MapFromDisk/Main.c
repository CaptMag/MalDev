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

	if (!ReadNtdll(&NtdllBuf))
	{
		PRINT_ERROR("ReadNtdll");
		return 1;
	}

	OKAY("Successfully Read Ntdll!");

	INFO("Comparing PE Headers...");

	CheckHeaders(NtdllHandle, NtdllBuf, &HookedNtdllTxt, &UnhookedNtdllTxt, &NtdllTxtSize);

	OKAY("Success");

	CHAR("Quit");
	getchar();

	return 0;

}