#include "box.h"

DWORD GetBaseHash
(
	IN char* FuncName,
	IN PVOID Dllbase,
	IN PIMAGE_EXPORT_DIRECTORY pImgExport
)
{

	UINT_PTR base = (UINT_PTR)Dllbase;
	UINT_PTR export = (UINT_PTR)base + pImgExport->AddressOfNames;

	UINT32 seed = (UINT32)((export >> 3) ^ (export << 13));

	UINT32 hash = FNV_OFFSET;

	hash ^= seed;
	hash *= FNV_PRIME;

	while (*FuncName)
	{
		hash ^= (UINT8)*FuncName++;
		hash *= FNV_PRIME;
	}

	return hash;

}

PVOID GetHashAddress
(
	IN PIMAGE_EXPORT_DIRECTORY pImgDir,
	IN PVOID Ntdllbase,
	IN DWORD ApiHash
)

{

	PDWORD Address = (PDWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgDir->NumberOfNames; i++)
	{


		CHAR* FuncName = (CHAR*)Ntdllbase + Name[i];

		if (ApiHash != GetBaseHash(FuncName, Ntdllbase, pImgDir))
			continue;
		WORD ord = Ordinal[i];
		PVOID FuncAddr = (LPBYTE)Ntdllbase + Address[ord];
		return FuncAddr;
	}

	return NULL;

}

PVOID GetModHandleWW
(
	IN wchar_t* target
)
{

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	INFO("PEB Address: [0x%p]", pPeb);
	INFO("Ldr Address: [0x%p]", pLdr);

	PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;

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
			return ModuleDll->DllBase;
		}
	}


	return NULL;
}

BOOL GrabPeHeader
(
	OUT PIMAGE_NT_HEADERS* pImgNt,
	OUT PIMAGE_SECTION_HEADER* pImgSecHeader,
	OUT PIMAGE_DATA_DIRECTORY* pImgDataDir,
	OUT PIMAGE_EXPORT_DIRECTORY* ppImgExpDir,
	IN HMODULE lpFile
)

{

	PBYTE pBase = (PBYTE)lpFile;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNt64 = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt64->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
		return FALSE;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = &pImgNt64->OptionalHeader;

	PIMAGE_SECTION_HEADER pImgSecHead = IMAGE_FIRST_SECTION(pImgNt64);

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)lpFile + pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PIMAGE_DATA_DIRECTORY pImgDataDir64 = &pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	*pImgNt = pImgNt64;
	*pImgSecHeader = pImgSecHead;
	*ppImgExpDir = pImgExpDir;
	*pImgDataDir = pImgDataDir64;

	return TRUE;

}

BOOL FixIAT
(
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN PIMAGE_EXPORT_DIRECTORY pImgDir,
	IN PBYTE dllBase
)
{

	HMODULE k32 = GetModHandleWW(L"Kernel32.dll");
	if (!k32)
	{
		PRINT_ERROR("GetModHandleWW");
		return FALSE;
	}

	DWORD LoadLibHash = GetBaseHash("LoadLibraryA", k32, pImgDir);
	fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetHashAddress(pImgDir, k32, LoadLibHash);
	if (!pLoadLibraryA)
	{
		PRINT_ERROR("pLoadLibraryA");
		return FALSE;
	}

	DWORD GetProcHash = GetBaseHash("GetProcAddress", k32, pImgDir);
	fnGetProcAddress pGetProcAddress = (fnGetProcAddress)GetHashAddress(pImgDir, k32, GetProcHash);
	if (!pGetProcAddress)
	{
		PRINT_ERROR("pGetProcAddress");
		return FALSE;
	}

	if (pImgDataDir->Size > 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dllBase + pImgDataDir->VirtualAddress);
		while (pImportDesc->Name)
		{

			LPSTR dllName = (LPSTR)((ULONGLONG)dllBase + pImportDesc->Name);
			HMODULE hModule = pLoadLibraryA(dllName);
			if (hModule)
			{
				PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(dllBase + pImportDesc->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(dllBase + pImportDesc->FirstThunk);

				if (!pOriginalThunk)
					pOriginalThunk = pFirstThunk;

				while (pOriginalThunk->u1.AddressOfData)
				{
					FARPROC funcAddr;
					if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
					{
						WORD FuncOrdinal = (WORD)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
						funcAddr = pGetProcAddress(hModule, (LPCSTR)FuncOrdinal);
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(dllBase + pOriginalThunk->u1.AddressOfData);
						funcAddr = pGetProcAddress(hModule, pImportByName->Name);
					}
					pFirstThunk->u1.Function = (ULONG_PTR)funcAddr;

					pOriginalThunk++;
					pFirstThunk++;
				}
			}
			pImportDesc++;
		}
	}

	FlushInstructionCache(GetCurrentProcess(), NULL, 0);

	return TRUE;

}