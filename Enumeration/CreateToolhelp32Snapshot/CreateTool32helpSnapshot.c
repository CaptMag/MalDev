#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

BOOL GetRemoteId
(
	LPCWSTR ProcName,
	OUT DWORD* PID
)

{

	HANDLE hSnap = NULL;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == NULL)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE;
	}

	if (Process32First(hSnap, &pe32))
	{
		while (_wcsicmp(pe32.szExeFile, ProcName) != 0)
		{
			Process32Next(hSnap, &pe32);
		}
	}

	*PID = pe32.th32ProcessID;

	return TRUE;

}

int main()
{

	DWORD PID = NULL;

	GetProcID(L"notepad.exe", &PID);

	return 0;

}
