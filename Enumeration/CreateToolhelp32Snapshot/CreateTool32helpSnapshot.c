#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

BOOL GetProcID
(
	LPCWSTR ProcName
)

{

	HANDLE hSnap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Failed!\n");
		return FALSE;
	}

	if (!Process32First(hSnap, &pe32))
	{
		printf("Failed To Enumerate 1st Process!\n");
		return FALSE;
	}

	if (Process32First(hSnap, &pe32))
	{
		while (_wcsicmp(pe32.szExeFile, ProcName) != 0)
		{
			Process32Next(hSnap, &pe32);
		}
		//printf("Found Process!");
	}

	printf("%ld", pe32.th32ProcessID);

	return TRUE;
}

int main()
{

	GetProcID(L"notepad.exe");

	return 0;

}