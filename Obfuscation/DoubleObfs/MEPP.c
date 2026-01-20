#include "box.h"

// https://malwaretech.com/wiki/locating-modules-via-the-peb-x64
// https://dev.to/wireless90/exploring-the-export-table-windows-pe-internals-4l47
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record

BOOL GetModHandleWW
(
	IN wchar_t* target,
	OUT PVOID* Ntdllbase
)
{

	PPEB pPeb = (PPEB)__readgsqword(0x60); // 64-bit to get PEB
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	INFO("PEB Address: [0x%p]", pPeb);
	INFO("Ldr Address: [0x%p]", pLdr);

	PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY entry = head->Flink;

	/*
	
		InLoadOrderModuleList Structure (usually)

		Iterating through pLdr->InLoadOrderModuleList.Flink

		Application.exe
		ntdll.dll
		kernel32.dll
		kernelbase.dll

	*/

	for (PLIST_ENTRY pList = head->Flink; pList != head; pList = pList->Flink)
	{

		PLDR_DATA_TABLE_ENTRY ModuleDll =
			CONTAINING_RECORD(
				pList, 
				LDR_DATA_TABLE_ENTRY, 
				InLoadOrderLinks
			);

		if (_wcsicmp(ModuleDll->BaseDllName.Buffer, target) == 0)
		{
			OKAY("Found Address for %ls | Base Address: [0x%p]", target, ModuleDll->DllBase);
			*Ntdllbase = ModuleDll->DllBase;
			if (Ntdllbase == NULL)
			{
				PRINT_ERROR("Ntdllbase");
				return FALSE;
			}
			break;
		}
	}


	return TRUE;
}

PVOID GetApiAddress
(
	IN PVOID BaseAddress,
	IN LPCSTR ApiName
)

{

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("pImgDos");
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("pImgNt");
		return NULL;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = (PIMAGE_OPTIONAL_HEADER)&pImgNt->OptionalHeader;

	PIMAGE_DATA_DIRECTORY pImgDataDir64 = &pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseAddress + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExport->NumberOfNames; i++)
	{

		/*
		
			Loop Through all functions
			Find the Name of the function
			Find their Base Address

		*/

		CHAR* FuncName = (CHAR*)BaseAddress + Name[i];

		if (strcmp(FuncName, ApiName) == 0)
		{
			DWORD ord = Ordinal[i];
			DWORD FuncRVA = Address[ord];

			PVOID FuncAddr = (PBYTE)BaseAddress + FuncRVA;

			INFO("Name: %s", FuncName);

			INFO("Ordinal: %ld | RVA: %ld | Address 0x%p",
				ord, FuncRVA, FuncAddr);

			return FuncAddr;
		}

	}

	return;
	
}

int main()
{

	PVOID Ntdllbase = NULL;
	const wchar_t* target = L"ntdll.dll";

	if (!GetModHandleWW(target, &Ntdllbase))
	{
		PRINT_ERROR("GetModHandleWW");
		return 1;
	}

	PVOID NtAlloc = GetApiAddress(Ntdllbase, "NtAllocateVirtualMemory");

	if (!NtAlloc)
	{
		PRINT_ERROR("GetApiAddress");
		return 1;
	}

	return 0;

}