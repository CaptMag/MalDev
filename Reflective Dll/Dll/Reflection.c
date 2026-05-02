#include "box.h"

extern void* __cdecl memcpy(void*, void*, size_t);
#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* pDestination, void* pSource, size_t sLength) {

	PBYTE D = (PBYTE)pDestination;
	PBYTE S = (PBYTE)pSource;

	while (sLength--)
		*D++ = *S++;

	return pDestination;
}

extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}

void pmemcpy(PVOID Dst, PVOID Src, SIZE_T Size) {
	for (SIZE_T i = 0; i < Size; i++)
		((PBYTE)Dst)[i] = ((PBYTE)Src)[i];
}

SIZE_T StringLengthA(IN LPCSTR String) {

	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

DWORD djb2(const char* str)
{
	DWORD hash = 5381;
	CHAR c;

	while ((c = *str++))
	{
		hash = ((hash << 5) + hash) + c;
	}

	return hash;
}

HMODULE GetModuleHandleH
(
	IN UINT32 ExportHash
)
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	if (!pPeb || !pLdr)
		return NULL;

	if (!ExportHash)
		return NULL;



	while (pDataTableEntry)
	{
		if (pDataTableEntry->FullDllName.Buffer && pDataTableEntry->FullDllName.Length < MAX_PATH)
		{
			CHAR Dllname[MAX_PATH] = { 0 };
			DWORD x = 0;

			while (pDataTableEntry->FullDllName.Buffer[x])
			{
				CHAR wc = pDataTableEntry->FullDllName.Buffer[x];
				if (wc >= 'A' && wc <= 'Z')
					Dllname[x] = wc - 'A' + 'a';

				else
					Dllname[x] = wc;

				x++;
			}

			Dllname[x] = '\0';

			if (djb2((PCHAR)Dllname) == ExportHash || pDataTableEntry->FullDllName.Buffer == ExportHash)
				return (HMODULE)pDataTableEntry->DllBase;
		}

		pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
	}

	return NULL;
}

PVOID GetHashAddress
(
	IN PVOID BaseAddress,
	IN ULONG64 ApiHash
)

{

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = (PIMAGE_OPTIONAL_HEADER)&pImgNt->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseAddress + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD pImgExportSize = pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PDWORD Address = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExport->NumberOfNames; i++)
	{


		CHAR* FuncName = (CHAR*)BaseAddress + Name[i];
		WORD ord = Ordinal[i];
		PVOID FuncAddr = (LPBYTE)BaseAddress + Address[ord];

		if (ApiHash == djb2(FuncName))
		{

			if ((((ULONG_PTR)FuncAddr) >= ((ULONG_PTR)pImgExport)) && (((ULONG_PTR)FuncAddr) < ((ULONG_PTR)pImgExport) + pImgExportSize))
			{

				CHAR ForwarderName[MAX_PATH] = { 0 };
				DWORD DotOffset = 0;
				PCHAR FunctionMod = NULL;
				PCHAR FunctionName = NULL;

				pmemcpy(ForwarderName, FuncAddr, StringLengthA((PCHAR)FuncAddr));

				for (int i = 0; i < StringLengthA((PCHAR)ForwarderName); i++)
				{

					if (((PCHAR)ForwarderName)[i] == '.')
					{
						DotOffset = i;
						ForwarderName[i] = NULL;
						break;
					}

				}

				FunctionMod = ForwarderName;
				FunctionName = ForwarderName + DotOffset + 1;

				LOADAPIHASH(fnLoadLibraryA, pLoadLibraryA, KERNEL32HASH, LOADLIBRARYAHASH);
				if (pLoadLibraryA)
					return GetHashAddress(pLoadLibraryA(FunctionMod), djb2(FunctionName));

			}
			return (FARPROC)FuncAddr;

		}
			
	}

	return NULL;

}

BOOL fixReloc
(
	IN DWORD RelocRVA,
	IN PVOID PeBase,
	IN DWORD_PTR dwDelta
)
{

	if (!PeBase || RelocRVA == 0)
		return FALSE;

	if (RelocRVA)
	{

		PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)PeBase + RelocRVA);

		while (Reloc->VirtualAddress)
		{
			DWORD size = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(Reloc + 1);

			for (DWORD i = 0; i < size; i++)
			{
				if (relocationRVA[i].Type == IMAGE_REL_BASED_DIR64)
				{
					ULONGLONG* PatchedAddress = (ULONGLONG*)((PBYTE)PeBase + Reloc->VirtualAddress + relocationRVA[i].Offset);
					*PatchedAddress += (ULONGLONG)dwDelta;
				}
			}
			Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)Reloc + Reloc->SizeOfBlock);
		}
	}

	return TRUE;

}

PVOID GetAddressByOrdinal(IN PVOID BaseAddress, IN WORD Ordinal)
{
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseAddress +
		pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfFunctions);

	// Subtract ordinal base to get the array index
	WORD Index = Ordinal - (WORD)pImgExport->Base;

	if (Index >= pImgExport->NumberOfFunctions)
		return NULL;

	return (PVOID)((LPBYTE)BaseAddress + Address[Index]);
}

BOOL FixIAT
(
	IN DWORD ImportRva,
	IN PBYTE PeBase
)
{

	LOADAPIHASH(fnLoadLibraryA, pLoadLibraryA, KERNEL32HASH, LOADLIBRARYAHASH);

	if (ImportRva)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(PeBase + ImportRva);

		while (pImport->Name)
		{
			HMODULE hDll = pLoadLibraryA((LPCSTR)(PeBase + pImport->Name));

			if (hDll)
			{
				PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(PeBase + pImport->FirstThunk);
				PIMAGE_THUNK_DATA pOriginalThunk = pImport->OriginalFirstThunk ?
					(PIMAGE_THUNK_DATA)(PeBase + pImport->OriginalFirstThunk) : pFirstThunk;

				while (pOriginalThunk->u1.AddressOfData)
				{
					FARPROC func = 0;

					if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
					{
						func = (FARPROC)GetAddressByOrdinal(hDll, (WORD)(pOriginalThunk->u1.Ordinal & 0xFFFF));
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(PeBase + pOriginalThunk->u1.AddressOfData);
						func = (FARPROC)GetHashAddress(hDll, djb2(pName->Name));
					}

					if (!func)
					{

						pFirstThunk->u1.Function = (ULONG_PTR)func;
						pFirstThunk++;
						pOriginalThunk++;
						continue;
					}
				}
			}

			pImport++;
		}
	}

	return TRUE;
}

BOOL ChangeProtection
(
	IN PVOID TargetBaseAddress,
	IN LPVOID lpFile
)
{
	LOADAPIHASH(PFN_VIRTUALPROTECT, pVirtualProtect, KERNEL32HASH, VIRTUALPROTECTHASH);

	PBYTE pBase = (PBYTE)lpFile;
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	PIMAGE_SECTION_HEADER pImgSec = IMAGE_FIRST_SECTION(pImgNt);

	for (int i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{

		DWORD dwProtection = 0;
		DWORD dwOldProt = 0;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if ((pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_READWRITE;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtection = PAGE_EXECUTE_READWRITE;
			else
				dwProtection = PAGE_EXECUTE_READ;
		}

		PVOID BaseAddress = (PVOID)((PBYTE)TargetBaseAddress + pImgSec[i].VirtualAddress);
		SIZE_T Size = pImgSec[i].SizeOfRawData;

		if (!pVirtualProtect(BaseAddress, Size, dwProtection, &dwOldProt))
		{
			return FALSE;
		}

	}

	return TRUE;

}

extern __declspec(dllexport) BOOL ReflectiveFunction()
{


	PIMAGE_DOS_HEADER pImgDos = NULL;
	PIMAGE_NT_HEADERS64 pImgNt = NULL;
	PIMAGE_DATA_DIRECTORY pImgDir = NULL;
	PBYTE PeBase = NULL;
	PBYTE ReflectiveDllBase = NULL;
	PDLLMAIN pDllMain = NULL;
	DWORD dwProt = 0;

	LOADAPIHASH(PFN_VIRTUALALLOC, pVirtualAlloc, KERNEL32HASH, VIRTUALALLOCHASH);
	LOADAPIHASH(PFN_VIRTUALPROTECT, pVirtualProtect, KERNEL32HASH, VIRTUALPROTECTHASH);

	ULONG_PTR currentAddr = (ULONG_PTR)_ReturnAddress();

	do
	{
		{
			pImgDos = (PIMAGE_DOS_HEADER)currentAddr;

			if (pImgDos->e_magic == IMAGE_DOS_SIGNATURE)
			{
				pImgNt = (PIMAGE_NT_HEADERS64)(currentAddr + pImgDos->e_lfanew);

				if (pImgNt->Signature == IMAGE_NT_SIGNATURE)
				{
					ReflectiveDllBase = (PBYTE)currentAddr;
					break;
				}
			}
		}

		currentAddr -= 0x1000;

	} while (TRUE);

	if (!ReflectiveDllBase)
		return FALSE;

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImgNt);

	if (!(PeBase = pVirtualAlloc(NULL, pImgNt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
	{
		return FALSE;
	}

	for (WORD i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{
		if (pSection->SizeOfRawData == 0)
			continue;

		pmemcpy(
			(PVOID)(PeBase + pSection->VirtualAddress),
			(PVOID)(ReflectiveDllBase + pSection->PointerToRawData),
			pSection->SizeOfRawData
		);
		pSection++;
	}

	PIMAGE_NT_HEADERS64 pImgNtNew = (PIMAGE_NT_HEADERS64)(PeBase + pImgDos->e_lfanew);
	DWORD_PTR dwDelta = (DWORD_PTR)PeBase - (DWORD_PTR)pImgNtNew->OptionalHeader.ImageBase;
	DWORD RelocRVA = pImgNtNew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (!fixReloc(RelocRVA, PeBase, dwDelta))
	{
		return FALSE;
	}

	DWORD IATRva = pImgNtNew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (!FixIAT(IATRva, PeBase))
	{
		return FALSE;
	}

	if (!ChangeProtection(PeBase, PeBase))
	{
		return FALSE;
	}

	pDllMain = (PDLLMAIN)(PeBase + pImgNtNew->OptionalHeader.AddressOfEntryPoint);
	pDllMain((HMODULE)PeBase, DLL_PROCESS_ATTACH, NULL);

	return TRUE;
}