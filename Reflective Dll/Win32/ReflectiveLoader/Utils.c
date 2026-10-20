#include "Utils.h"

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

DWORD djb2W(const PWSTR str, SIZE_T length)
{

	//------------------------------------------------------

	DWORD	hash = HASH_SEED;
	PUCHAR	Ptr = (PUCHAR)str;

	//------------------------------------------------------

	do
	{
		UCHAR Char = *Ptr;

		if (!length)
		{
			if (!*Ptr)
				break;
		}
		else
		{
			if ((ULONG)(Ptr - (PUCHAR)str) >= length)
				break;

			if (!*Ptr)
				Ptr++;
		}

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	//------------------------------------------------------

	return hash;
}

DWORD djb2A(const char* str)
{

	//------------------------------------------------------

	DWORD	hash = 5381;
	PUCHAR	Ptr = str;

	//------------------------------------------------------

	do
	{

		UCHAR Char = *Ptr;

		if (!*Ptr) break;

		if (!*Ptr)
			Ptr++;

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	//------------------------------------------------------

	return hash;
}

DWORD STRLEN
(
	_In_ LPCSTR String
)
{

	LPCSTR String2 = NULL;

	for (String2 = String; *String2; ++String2);
	return(String2 - String);

}

SIZE_T WCSLEN
(
	_In_ LPCWSTR String
)
{

	LPCWSTR String2 = NULL;

	for (String2 = String; *String2; ++String2);
	return(String2 - String);

}

VOID MEMCPY
(
	_In_ PVOID	Destination,
	_In_ PVOID	Source,
	_In_ SIZE_T Size
)
{

	PCHAR D = (PCHAR)Destination;
	PCHAR S = (PCHAR)Source;

	for (SIZE_T i = 0; i < Size; i++)
		D[i] = S[i];

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

HMODULE GetHashedModuleHandle
(
	_In_ DWORD DllModuleHash
)
{

	//------------------------------------------------------

	PPEB					pPeb				= (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA			pLdr				= (PPEB_LDR_DATA)pPeb->Ldr;
	PLIST_ENTRY				Head				= &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY				pList				= Head->Flink;
	PLDR_DATA_TABLE_ENTRY	pDataLdr			= NULL;

	PVOID					ModuleBaseAddress	= NULL;

	//------------------------------------------------------

	for (pList; pList != Head; pList = pList->Flink)
	{

		pDataLdr = (PLDR_DATA_TABLE_ENTRY)pList;

		if (djb2W(pDataLdr->BaseDllName.Buffer, pDataLdr->BaseDllName.Length) == DllModuleHash)
		{
			ModuleBaseAddress = pDataLdr->DllBase;
			break;
		}

	}

	//------------------------------------------------------

	return ((ModuleBaseAddress != NULL)) ? ModuleBaseAddress : NULL;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

PVOID ResolveHashedFunctionEx
(
	_In_		REF_LDR*	RefLdrApi,
	_In_		PVOID		ModuleBaseAddress,
	_In_		DWORD		FunctionHash,
	_In_opt_	ULONG		FunctionOrdinal
)
{

	//------------------------------------------------------

	PIMAGE_NT_HEADERS64		pImageNtHeader			= NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory	= NULL;
	PDWORD					AddressOfFunctions		= NULL;
	PDWORD					AddressOfNames			= NULL;
	PWORD					AddressOfNamesOrdinals	= NULL;

	PCHAR					FunctionName			= NULL;
	PVOID					FunctionAddress			= NULL;
	PCHAR					FunctionMod				= NULL;
	CHAR					ForwarderName[MAX_PATH] = { 0 };
	DWORD					DotOffset				= 0;
	DWORD					OrdinalIndex			= 0;
	SIZE_T					ExportDirectorySize		= 0;

	//------------------------------------------------------

	pImageNtHeader			= (PIMAGE_NT_HEADERS64)(U_PTR(ModuleBaseAddress) + ((PIMAGE_DOS_HEADER)ModuleBaseAddress)->e_lfanew);
	pImageExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)(U_PTR(ModuleBaseAddress) + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	ExportDirectorySize		= pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	AddressOfNames			= C_PTR(U_PTR(ModuleBaseAddress) + pImageExportDirectory->AddressOfNames);
	AddressOfFunctions		= C_PTR(U_PTR(ModuleBaseAddress) + pImageExportDirectory->AddressOfFunctions);
	AddressOfNamesOrdinals	= C_PTR(U_PTR(ModuleBaseAddress) + pImageExportDirectory->AddressOfNameOrdinals);

	//------------------------------------------------------

	for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
	{

		//------------------------------------------------------

		if (FunctionOrdinal != 0)
		{

			OrdinalIndex	= FunctionOrdinal - pImageExportDirectory->Base;
			FunctionAddress = C_PTR(U_PTR(ModuleBaseAddress) + AddressOfFunctions[OrdinalIndex]);

			return FunctionAddress;

		}

		//------------------------------------------------------

		else
		{

			FunctionName = (PCHAR)(U_PTR(ModuleBaseAddress) + AddressOfNames[i]);

			if (djb2A(FunctionName) == FunctionHash)
			{

				FunctionAddress = C_PTR(U_PTR(ModuleBaseAddress) + AddressOfFunctions[AddressOfNamesOrdinals[i]]);

				if (U_PTR(FunctionAddress) >= U_PTR(pImageExportDirectory) && U_PTR(FunctionAddress) < U_PTR(pImageExportDirectory + ExportDirectorySize))
				{

					//------------------------------------------------------

					MEMCPY(ForwarderName, FunctionAddress, STRLEN((LPCSTR)FunctionAddress));

					for (SIZE_T i = 0; i < STRLEN((LPCSTR)ForwarderName); i++)
					{

						if (((PCHAR)ForwarderName)[i] == '.')
						{
							DotOffset = i;
							ForwarderName[i] = 0;
							break;
						}

					}

					FunctionMod		= ForwarderName;
					FunctionName	= ForwarderName + DotOffset + 1;

					if (RefLdrApi->Api.pLoadLibraryA)
						return ResolveHashedFunctionEx(RefLdrApi, RefLdrApi->Api.pLoadLibraryA(FunctionMod), djb2A(FunctionName), 0);

					//------------------------------------------------------

				}

				return ((FunctionAddress != NULL)) ? FunctionAddress : NULL;
			}

		}

		//------------------------------------------------------

	}

	return NULL;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN ResolveImportAddressTable
(
	_In_	PVOID		ImageBaseAddress,
	_In_	REF_LDR*	RefLdrApi
)
{

	//------------------------------------------------------

	PIMAGE_THUNK_DATA			pOriginalThunkData			= NULL;
	PIMAGE_THUNK_DATA			pFirstThunkData				= NULL;

	PIMAGE_IMPORT_DESCRIPTOR	pImageImportDescriptor		= NULL;
	PIMAGE_IMPORT_BY_NAME		pImageImportByName			= NULL;

	PCHAR						ImportModuleName			= NULL;
	HMODULE						ImportModule				= NULL;

	PVOID						Function					= NULL;
	LPVOID						ImportAddressTableDirectory = NULL;

	//------------------------------------------------------

	ImportAddressTableDirectory = C_PTR(U_PTR(ImageBaseAddress) + RefLdrApi->PeHeaders.pEntryImportDataDir->VirtualAddress);

	for (pImageImportDescriptor = ImportAddressTableDirectory; pImageImportDescriptor->Name != 0; ++pImageImportDescriptor)
	{

		//------------------------------------------------------

		pOriginalThunkData	= (PIMAGE_THUNK_DATA)(U_PTR(ImageBaseAddress) + pImageImportDescriptor->OriginalFirstThunk);
		pFirstThunkData		= (PIMAGE_THUNK_DATA)(U_PTR(ImageBaseAddress) + pImageImportDescriptor->FirstThunk);
		ImportModuleName	= (PCHAR)(U_PTR(ImageBaseAddress) + pImageImportDescriptor->Name);

		if ((ImportModule	= RefLdrApi->Api.pLoadLibraryA(ImportModuleName)) == NULL)
			return FALSE;

		//------------------------------------------------------

		for (; pOriginalThunkData->u1.AddressOfData != 0; ++pOriginalThunkData, ++pFirstThunkData)
		{

			//------------------------------------------------------

			if (pOriginalThunkData->u1.Function == 0 && pFirstThunkData->u1.Function == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunkData->u1.Ordinal))
			{

				if ((Function = ResolveHashedFunctionEx(RefLdrApi, ImportModule, 0, IMAGE_ORDINAL(pOriginalThunkData->u1.Ordinal))) == NULL)
				{
					return FALSE;
				}

				if (Function != NULL)
					pFirstThunkData->u1.Function = (ULONGLONG)Function;

			}

			//------------------------------------------------------

			else
			{

				pImageImportByName = C_PTR(U_PTR(ImageBaseAddress) + pOriginalThunkData->u1.AddressOfData);

				if ((Function = ResolveHashedFunctionEx(RefLdrApi, ImportModule, djb2A(pImageImportByName->Name), 0)) == NULL)
				{
					return FALSE;
				}

				if (Function != NULL)
					pFirstThunkData->u1.Function = (ULONGLONG)Function;

			}

			//------------------------------------------------------

		}

	}

	return ((Function != NULL)) ? TRUE : FALSE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN ProcessSectionRelocations
(
	_In_	DWORD		RVA,
	_In_	PVOID		ImageBase,
	_In_	DWORD_PTR	Delta
)
{

	//------------------------------------------------------

	PIMAGE_BASE_RELOCATION	Reloc		= NULL;
	PBASE_RELOCATION_ENTRY	RelocEntry	= NULL;
	DWORD					Size		= 0;

	Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)ImageBase + RVA);

	//------------------------------------------------------

	while (Reloc->VirtualAddress != 0)
	{

		Size = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		RelocEntry = (PBASE_RELOCATION_ENTRY)(Reloc + 1);

		for (DWORD i = 0; i < Size; i++)
		{

			//------------------------------------------------------

			switch (RelocEntry[i].Type)
			{
				case IMAGE_REL_BASED_DIR64:
				{
					ULONGLONG* PatchedAddress = (ULONGLONG*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += (ULONGLONG)Delta;
					break;
				}
				case IMAGE_REL_BASED_HIGHLOW:
				{
					DWORD* PatchedAddress = (DWORD*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += (DWORD)Delta;
					break;
				}
				case IMAGE_REL_BASED_HIGH:
				{
					WORD* PatchedAddress = (WORD*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += HIWORD(Delta);
					break;
				}
				case IMAGE_REL_BASED_LOW:
				{
					WORD* PatchedAddress = (WORD*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += LOWORD(Delta);
					break;
				}
				case IMAGE_REL_BASED_ABSOLUTE:
					continue;
			}

			//------------------------------------------------------

		}
		Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)Reloc + Reloc->SizeOfBlock);

	}

	//------------------------------------------------------

	return ((Reloc != NULL)) ? TRUE : FALSE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

BOOLEAN ChangeMemoryProtection
(
	_In_	REF_LDR*	RefLdrApi,
	_In_	PVOID		TargetBaseAddress
)
{

	//------------------------------------------------------

	PIMAGE_SECTION_HEADER pImgSec = IMAGE_FIRST_SECTION(RefLdrApi->PeHeaders.pImgNtHdrs);

	for (int i = 0; i < RefLdrApi->PeHeaders.pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{

		//------------------------------------------------------

		ULONG ulProtection	= 0;
		ULONG ulOldProt		= 0;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			ulProtection = PAGE_EXECUTE;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ)
			ulProtection = PAGE_READONLY;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			ulProtection = PAGE_WRITECOPY;

		if ((pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			ulProtection = PAGE_READWRITE;

		if ((pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			ulProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ))
			ulProtection = PAGE_EXECUTE_READ;

		if ((pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ))
			ulProtection = PAGE_EXECUTE_READWRITE;

		//------------------------------------------------------

		PVOID BaseAddress = C_PTR((U_PTR(TargetBaseAddress) + pImgSec[i].VirtualAddress));
		SIZE_T Size = pImgSec[i].SizeOfRawData;

		if (!RefLdrApi->Api.pVirtualProtect(BaseAddress, Size, ulProtection, &ulOldProt))
		{
			return FALSE;
		}

		//------------------------------------------------------

	}

	//------------------------------------------------------

	return TRUE;

}

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=