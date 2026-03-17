#include "box.h"

BOOL SelfDelete()
{

	WCHAR					szPath[MAX_PATH * 2]		= { 0 };
	FILE_DISPOSITION_INFO	Delete						= { 0 };
	HANDLE					hFile						= INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename						= { 0 };
	LPWSTR					lpwStream					= L":blahblahblah";
	DWORD					dwRename					= (DWORD)(wcslen(lpwStream)) * sizeof(WCHAR),
							bsfRename					= sizeof(FILE_RENAME_INFO) + dwRename;

	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bsfRename);
	if (!pRename)
	{
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	Delete.DeleteFile = TRUE;

	pRename->ReplaceIfExists = TRUE;
	pRename->RootDirectory = NULL;
	pRename->FileNameLength = dwRename;
	RtlCopyMemory(pRename->FileName, lpwStream, dwRename);

	if (!GetModuleFileNameW(NULL, szPath, MAX_PATH * 2))
	{
		PRINT_ERROR("GetModuleFileNameW");
		return FALSE;
	}

	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileW");
		return FALSE;
	}

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, bsfRename))
	{
		PRINT_ERROR("SetFileInformationByHandle");
		return FALSE;
	}

	CloseHandle(hFile);

	hFile = CreateFileW(szPath, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileW");
		return FALSE;
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete)))
	{
		PRINT_ERROR("SetFileInformationByHandle");
		return FALSE;
	}

	CloseHandle(hFile);
	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;

}