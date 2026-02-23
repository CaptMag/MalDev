#include "box.h"

int main()
{

	PVOID	NtdllBuf			= NULL,
			HookedNtdllTxt		= NULL, 
			UnhookedNtdllTxt	= NULL;
	SIZE_T	NtdllTxtSize		= 0;
	DWORD	PID					= 0;
	HANDLE	hProcess			= NULL, 
			hThread				= NULL;

	HMODULE NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NtdllHandle == NULL)
	{
		PRINT_ERROR("GetModuleHandleW");
		return 1;
	}

	if (!CreateSuspendedProcess("notepad.exe", &hProcess, &hThread, &PID, &NtdllBuf))

	OKAY("Successfully Read Ntdll!");

	INFO("Comparing PE Headers...");

	CheckHeaders(NtdllHandle, NtdllBuf, &HookedNtdllTxt, &UnhookedNtdllTxt, &NtdllTxtSize);

	OKAY("Success");

	CHAR("Quit");
	getchar();

	return 0;

	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);

}