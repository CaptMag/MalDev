#include "NtdllUnhooking.h"

#define NTDLL_PATH L"C:\\Windows\\System32\\Ntdll.dll"

BOOL OpenDllFile
(
	_In_	LPCWSTR DllPath,
	_Out_	LPVOID* lpBuffer
)
{

	HANDLE	hFile				= NULL;
	BOOL	State				= TRUE;
	DWORD	lpNumberOfBytesRead = 0;
	DWORD	NumberOfBytesRead	= 0;

	if (!DllPath || !lpBuffer)
		return FALSE;

	if ((hFile = CreateFileW(DllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == NULL)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Current File Handle", hFile);

	if ((NumberOfBytesRead = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Current File Size", NumberOfBytesRead);

	if ((*lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytesRead)) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Allocated Bytes to Buffer", NumberOfBytesRead);

	if (!ReadFile(hFile, *lpBuffer, NumberOfBytesRead, &lpNumberOfBytesRead, NULL))
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto _END_FUNC;
	}

	OKAY("Successfully Read File!");

_END_FUNC:

	if (hFile)
		CloseHandle(hFile);

	return State;

}

HMODULE GetLocalNtdllHandle(void)
{

	PPEB					pPeb		= (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)pPeb->Ldr;
	PLIST_ENTRY				Head		= &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY				pList		= Head->Flink;
	PLDR_DATA_TABLE_ENTRY	pDataLdr	= NULL;

	for (pList; pList != Head; pList = pList->Flink)
	{

		pDataLdr = CONTAINING_RECORD(
			pList,
			LDR_DATA_TABLE_ENTRY,
			InMemoryOrderLinks
		);

		if (pDataLdr->BaseDllName.Buffer &&_wcsicmp(pDataLdr->BaseDllName.Buffer, L"ntdll.dll") == 0)
			return (HMODULE)pDataLdr->DllBase;

	}

	return NULL;

}

BOOL WriteUnhookedNtdll
(
	_In_ PVOID	HookedNtdll,
	_In_ PVOID	UnhookedNtdll,
	_In_ SIZE_T TextSectionSize
)
{

	DWORD OldProtection = 0;

	if (!VirtualProtect(HookedNtdll, TextSectionSize, PAGE_EXECUTE_WRITECOPY, &OldProtection))
	{
		WARN("Failed to Change Memory Protections! PAGE_EXECUTE_WRITECOPY");
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Current Memory Protection: WX");

	RtlCopyMemory(HookedNtdll, UnhookedNtdll, TextSectionSize);

	INFO("Copied Unhooked Ntdll to Hooked Ntdll!");
	INFO("[0x%p] --> [0x%p] w/ Size [%zu]", HookedNtdll, UnhookedNtdll, TextSectionSize);

	if (!VirtualProtect(HookedNtdll, TextSectionSize, OldProtection, &OldProtection))
	{
		WARN("Failed to Revert Memory Protections!");
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Reverted Memory Protection!");

	return TRUE;

}

BOOL ReplaceNtdll
(
	_In_ PVOID UnhookedNtdll
)
{

	PIMAGE_NT_HEADERS64		pImageNtHeader				= NULL;
	PIMAGE_SECTION_HEADER	pImageSection				= NULL;
	PVOID					HookedNtdllTextSection		= NULL;
	PVOID					UnhookedNtdllTextSection	= NULL;
	SIZE_T					TextSectionSize				= 0;
	HMODULE					Ntdll						= GetLocalNtdllHandle();

	INFO("[0x%p] Local Ntdll", Ntdll);

	pImageNtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)Ntdll + ((PIMAGE_DOS_HEADER)Ntdll)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pImageSection = IMAGE_FIRST_SECTION(pImageNtHeader);
	for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{

		if (strcmp(pImageSection[i].Name, ".text") == 0)
		{

			HookedNtdllTextSection = (PVOID)((ULONG_PTR)Ntdll + pImageSection->VirtualAddress);

			UnhookedNtdllTextSection = (PVOID)((ULONG_PTR)UnhookedNtdll + pImageSection->VirtualAddress);

			TextSectionSize = pImageSection[i].Misc.VirtualSize;
			break;

		}

	}

	INFO("Hooked Ntdll Text Section [0x%p] ", HookedNtdllTextSection);
	INFO("Unhooked Ntdll Text Section [0x%p]", UnhookedNtdllTextSection);
	INFO("Hooked Ntdll [0x%p] || Unhooked Ntdll [0x%p]", Ntdll, UnhookedNtdll);

	if (!WriteUnhookedNtdll(HookedNtdllTextSection, UnhookedNtdllTextSection, TextSectionSize))
	{
		PRINT_ERROR("WriteUnhookedNtdll");
		return FALSE;
	}

	return TRUE;

}

VOID CheckForHookedNtApi
(
	_In_ PVOID Nt_FunctionAddress
)
{

	// mov r10, rcx
	// mov rax, ???
	BYTE	OriginalByteSequence[]	= { 0x4C, 0x8B, 0xD1, 0xB8 };
	SIZE_T	BytesSize				= sizeof(OriginalByteSequence);
	PVOID	CleanNtdll				= NULL;

	OpenDllFile(NTDLL_PATH, &CleanNtdll);

	if (memcmp(Nt_FunctionAddress, OriginalByteSequence, BytesSize) != 0) // different bytes
	{

		if (OriginalByteSequence[0] == JMP || OriginalByteSequence[0] == CALL) // E9 or E8 detected
		{
			WARN("Potentially Hooked Function!");
			ReplaceNtdll(CleanNtdll);
		}
		INFO("Continuing Execution. Address: 0x%p", Nt_FunctionAddress);

	}
	else
	{
		INFO("Continuing Execution. Address: 0x%p", Nt_FunctionAddress);
	}

}