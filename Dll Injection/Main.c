#include "DllInjector.h"

#define TARGET_PROCESS L"notepad.exe"

int main()
{

	LPCWSTR DllPath					= L".\\Dll\\Dll.dll";
	WCHAR	FullDllPath[MAX_PATH]	= { 0 };

	HANDLE	ProcessHandle			= NULL;
	HANDLE	ThreadHandle			= NULL;

	DWORD	ProcessId				= 0;
	SIZE_T	PayloadSize				= 0;

	if (GetFullPathNameW(DllPath, MAX_PATH, FullDllPath, NULL) == 0)
	{
		PRINT_ERROR("GetFullPathNameW");
		return 1;
	}

	INFO("Full Path: %ls", FullDllPath);

	PayloadSize = (wcslen(FullDllPath) + 1) * sizeof(WCHAR);

	if (!GetProcessHandleAndPid(TARGET_PROCESS, &ProcessHandle, &ProcessId))
	{
		PRINT_ERROR("GetProcessHandleAndPid");
		return 1;
	}

	if (!DllInjection(ProcessHandle, FullDllPath, PayloadSize, ProcessId))
	{
		PRINT_ERROR("DllInjection");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}