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