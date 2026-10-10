#include "SelfDelete.h"

// References:
// https://tkyn.dev/2025-6-8-The-Not-So-Self-Deleting-Executable-on-24h2/
// https://github.com/MaangoTaachyon/SelfDeletion-Updated

BOOLEAN DeleteCurrentFile(void)
{

	NTSTATUS						Status							= STATUS_SUCCESS;
	BOOLEAN							State							= TRUE;

	PVOID							Ntdll							= NULL;
	PVOID							FileHandle						= NULL;
	SIZE_T							RenameSize						= 0;
	PFILE_RENAME_INFO				FileRename						= { 0 };
	IO_STATUS_BLOCK					iosb							= { 0 };
	FILE_DISPOSITION_INFORMATION_EX FileDisposition					= { 0 };

	LPCWSTR							Stream							= L":TKYN";
	WCHAR							RunningFilePath[MAX_PATH]		= { 0 };

	NtSetInformationFile_t			NtSetInformationFile			= { 0 };

	Ntdll = GetModuleHandleW(L"Ntdll.dll");
	GetModuleFileNameW(NULL, RunningFilePath, MAX_PATH);
	NtSetInformationFile = (NtSetInformationFile_t)GetProcAddress(Ntdll, "NtSetInformationFile");

	INFO("Running Executable: %ls", RunningFilePath);

	if ((FileHandle = CreateFileW(RunningFilePath, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileW");
		State = FALSE; goto _END_FUNC;
	}

	RenameSize = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * (wcslen(Stream) + 1);
	FileRename = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RenameSize);

	FileRename->FileNameLength = (DWORD)(wcslen(Stream) * sizeof(wchar_t));
	RtlCopyMemory(FileRename->FileName, Stream, FileRename->FileNameLength);

	if (!SetFileInformationByHandle(FileHandle, FileRenameInfo, FileRename, (DWORD)RenameSize))
	{
		PRINT_ERROR("SetFileInformationByHandle");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Renamed Data Stream");

	CloseHandle(FileHandle);
	FileHandle = INVALID_HANDLE_VALUE;

	if ((FileHandle = CreateFileW(RunningFilePath, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileW");
		State = FALSE; goto _END_FUNC;
	}

	FileDisposition.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS;
	if (!NT_SUCCESS(NtSetInformationFile(FileHandle, &iosb, &FileDisposition, sizeof(FileDisposition), FileDispositionInformationEx)))
	{
		NT_ERROR("NtSetInformationFile");
		State = FALSE; goto _END_FUNC;
	}

	OKAY("Success!");

_END_FUNC:

	if (FileHandle && FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileHandle);

	if (FileRename)
		HeapFree(GetProcessHeap(), 0, FileRename);

	return State;

}