#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

BOOL GetRemoteId
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{
	BOOL found = FALSE;
	HANDLE hSnap = NULL;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == NULL)
	{
		printf("CreateToolhelp32Snapshot: %lu", GetLastError());
		return FALSE;
	}

	INFO("[0x%p] Acquired Handle to hSnap", hSnap);

	if (Process32FirstW(hSnap, &pe32))
	{
		do
		{
			if (_wcsicmp(pe32.szExeFile, ProcName) == 0)
			{
				*PID = pe32.th32ProcessID;

				*hProcess = OpenProcess(
					PROCESS_ALL_ACCESS,
					FALSE,
					pe32.th32ProcessID
				);

				if (*hProcess == NULL)
				{
					printf("OpenProcess failed: %lu\n", GetLastError());
					CloseHandle(hSnap);
					return FALSE;
				}

				found = TRUE;
				break;
			}

		} while (Process32Next(hSnap, &pe32));
	}

	CloseHandle(hSnap);
	return found;

}

int main()
{

	DWORD PID = NULL;
	HANDLE hProcess = NULL;

	GetRemoteId(L"notepad.exe", &PID, &hProcess);
	if (GetRemoteId == NULL)
	{
		printf("GetRemoteId Failed: %lu", GetLastError());
		return 1;
	}

	return 0;

}
