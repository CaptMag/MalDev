#include "box.h"
#include "structs.h"

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
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		printf("[!] HeapAlloc Failed!\n");
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
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

BOOL InjectDll
(
	IN LPCSTR dllPath,
	IN HANDLE hProcess,
	IN DWORD PID
)
{

	DWORD TID;
	PVOID rBuffer;
	HANDLE hThread;
	SIZE_T BytesWritten;

	SIZE_T dllSize = strlen(dllPath) + 1;

	INFO("[%s] Current Dll Path", dllPath);

	HMODULE Kernel32 = GetModuleHandleA("Kernel32.dll");
	if (Kernel32 == NULL)
	{
		PRINT_ERROR("GetModuleHandle!");
		return FALSE;
	}

	INFO("[0x%p] Current K32 Address", Kernel32);

	PVOID pLoadLib = GetProcAddress(Kernel32, "LoadLibraryA");
	if (pLoadLib == NULL)
	{
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	OKAY("[0x%p] LoadLibraryA Address", pLoadLib);

	INFO("[0x%p] Current Process Handle", hProcess);
	INFO("[%ld] Current PID", PID);

	rBuffer = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!rBuffer)
	{
		PRINT_ERROR("VirtualAllocEx");
		return FALSE;
	}

	OKAY("[0x%p] [RW-] allocated a buffer with PAGE_READWRITE [RW-] permissions!", rBuffer);

	if (!WriteProcessMemory(hProcess, rBuffer, dllPath, dllSize, &BytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		return FALSE;
	}

	OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer", rBuffer, BytesWritten);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, rBuffer, 0, &TID);
	if (!hThread)
	{
		PRINT_ERROR("CreateRemoteThread");
		return FALSE;
	}

	INFO("Waiting...");
	WaitForSingleObject(hThread, INFINITE);
	OKAY("Done!");

	CloseHandle(hThread);

	return TRUE;

}