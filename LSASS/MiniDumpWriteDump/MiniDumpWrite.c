#include "box.h"
#include "structs.h"

// https://www.debuginfo.com/examples/src/effminidumps/MiniDump.cpp
// 

BOOL GetRemoteProcID
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = 0, uReturnLen2 = 0;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = 0;


	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		PRINT_ERROR("NtQuerySystemInformation");
		return FALSE;
	}

	while (TRUE) {
		if (SystemProcInfo->ImageName.Length && _wcsicmp(SystemProcInfo->ImageName.Buffer, ProcName) == 0)
		{
			*PID = (DWORD)SystemProcInfo->UniqueProcessId;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	if (*PID == NULL || *hProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL DumpViaMiniDump
(
	IN LPCSTR FileName,
	IN HANDLE hProcess,
	IN DWORD PID
)
{

	if (!hProcess || !PID)
		return FALSE;
	
	HANDLE hFile = INVALID_HANDLE_VALUE;
	MINIDUMP_CALLBACK_INFORMATION MiniDumpInfo = { 0 };
	RtlSecureZeroMemory(&MiniDumpInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	
	MiniDumpInfo.CallbackRoutine = MiniDumpCallBack;
	MiniDumpInfo.CallbackParam = 0;

	hFile = CreateFileA(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Create a Dump File!");
		PRINT_ERROR("CreateFileA");
		return FALSE;
	}

	if (!MiniDumpWriteDump(
		hProcess,
		PID,
		hFile,
		MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithThreadInfo,
		NULL,
		NULL,
		&MiniDumpInfo
	))
	{
		WARN("Failed to Write Dump!");
		PRINT_ERROR("MiniDumpWriteDump");
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;

}

BOOL CALLBACK MiniDumpCallBack
(
	PVOID pParam,
	PMINIDUMP_CALLBACK_INPUT pInput,
	PMINIDUMP_CALLBACK_OUTPUT pOutput
)
{

	/*
	
		For this we will be defining which callbacks we want to have included via
		the PMINIDUMP_CALLBACK_INPUT struct. This will be used as our CallBackRoutine
		for MINIDUMP_CALLBACK_INFORMATION.

	*/

	BOOL CallbackReturn = FALSE;

	switch (pInput->CallbackType)
	{

	case ThreadCallback:
		CallbackReturn = TRUE;
		break;
	case ThreadExCallback:
		CallbackReturn = TRUE;
		break;
	case ModuleCallback:
		CallbackReturn = TRUE;
		break;
	case IncludeModuleCallback:
		CallbackReturn = TRUE;
		break;
	case IncludeThreadCallback:
		CallbackReturn = TRUE;
		break;
	case MemoryCallback:
		CallbackReturn = FALSE;
		break;
	case CancelCallback:
		CallbackReturn = FALSE;
		break;

	default:
		CallbackReturn = FALSE;
		break;

	}

	return CallbackReturn;

}