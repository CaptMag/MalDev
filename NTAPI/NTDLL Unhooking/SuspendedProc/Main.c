#include "box.h"

int main()
{

	PVOID NtdllBuf = NULL;
	PVOID HookedNtdllTxt, UnhookedNtdllTxt = NULL;
	SIZE_T NtdllTxtSize = NULL;
	DWORD PID = NULL;
	HANDLE hProcess, hThread = NULL;

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

	CheckState(HookedNtdllTxt, UnhookedNtdllTxt, NtdllTxtSize);

	OKAY("Completed State Check!");

	CHAR("Quit");
	getchar();

	return 0;

	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);

}