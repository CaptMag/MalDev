#include "Win32.h"

DWORD djb2W(const PWSTR str, SIZE_T length)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = (PUCHAR)str;

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

	return hash;
}

DWORD djb2A(const char* str)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = str;

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

	return hash;
}

DWORD StringLengthA
(
	_In_ LPCSTR String
)
{

	LPCSTR String2 = NULL;

	for (String2 = String; *String2; ++String2);
	return(String2 - String);

}

SIZE_T StringLengthW
(
	_In_ LPCWSTR String
)
{

	LPCWSTR String2 = NULL;

	for (String2 = String; *String2; ++String2);
	return(String2 - String);

}

PVOID NativeLoadLibrary
(
	IN LPSTR ModuleName,
	IN pWin32 Win32
)
{

	if (!ModuleName)
		return NULL;

	NTSTATUS					Status			= STATUS_SUCCESS;
	WCHAR						ModuleW[260]	= { 0 };
	ULONG						Size			= StringLengthA(ModuleName);
	UNICODE_STRING				uString			= { 0 };
	PVOID						pModule			= NULL;


	// convert to wchar
	if (!NT_SUCCESS(Status = Win32->Api.RtlMultiByteToUnicodeN(ModuleW, sizeof(ModuleW), &Size, ModuleName, StringLengthA(ModuleName) + 1)))
	{
		return NULL;
	}

	// thanks to KaynLdr :)
	if (ModuleW)
	{

		USHORT DestSize			= StringLengthW(ModuleW) * sizeof(WCHAR);
		uString.Length			= DestSize;
		uString.MaximumLength	= DestSize + sizeof(WCHAR);

	}

	uString.Buffer = ModuleW;

	if (!NT_SUCCESS(Status = Win32->Api.LdrLoadDll(NULL, 0, &uString, &pModule)))
		return NULL;

	return pModule;

}

PVOID GetModuleByHash
(
	_In_ DWORD ModuleHash
)
{

	PPEB					pPeb		= (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)pPeb->Ldr;
	PLIST_ENTRY				Head		= &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY				pList		= Head->Flink;
	PLDR_DATA_TABLE_ENTRY	pDataLdr	= NULL;

	for (pList; pList != Head; pList = pList->Flink)
	{

		pDataLdr = (PLDR_DATA_TABLE_ENTRY)pList;

		if (djb2W(pDataLdr->BaseDllName.Buffer, pDataLdr->BaseDllName.Length) == ModuleHash)
			return pDataLdr->DllBase;

	}

	return NULL;

}

PVOID ResolveHashedFunction
(
	_In_ pWin32 Win32,
	_In_ PVOID DllModuleBase,
	_In_ DWORD FunctionHash
)
{

	PIMAGE_NT_HEADERS64		pImageNtHeader			= NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory	= NULL;
	SIZE_T					ExportDirectorySize		= 0;

	PDWORD					AddressOfFunctions		= NULL;
	PDWORD					AddressOfNames			= NULL;
	PWORD					AddressOfNamesOrdinals	= NULL;
	
	PVOID					FunctionAddress			= NULL;
	PCHAR					FunctionName			= NULL;

	CHAR					ForwarderName[MAX_PATH] = { 0 };
	DWORD					DotOffset				= 0;
	PCHAR					FunctionMod				= NULL;

	pImageNtHeader			= (PIMAGE_NT_HEADERS64)(U_PTR(DllModuleBase) + ((PIMAGE_DOS_HEADER)DllModuleBase)->e_lfanew);
	pImageExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)(U_PTR(DllModuleBase) + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	ExportDirectorySize		= pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	AddressOfFunctions		= C_PTR(U_PTR(DllModuleBase) + pImageExportDirectory->AddressOfFunctions);
	AddressOfNames			= C_PTR(U_PTR(DllModuleBase) + pImageExportDirectory->AddressOfNames);
	AddressOfNamesOrdinals	= C_PTR(U_PTR(DllModuleBase) + pImageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
	{

		FunctionName = (PCHAR)(U_PTR(DllModuleBase) + AddressOfNames[i]);

		if (djb2A(FunctionName) == FunctionHash)
		{

			FunctionAddress = C_PTR(U_PTR(DllModuleBase) + AddressOfFunctions[AddressOfNamesOrdinals[i]]);

			if (U_PTR(FunctionAddress) >= U_PTR(pImageExportDirectory) && U_PTR(FunctionAddress) < U_PTR(pImageExportDirectory + ExportDirectorySize))
			{

				__movsb(ForwarderName, FunctionAddress, StringLengthA((LPCSTR)FunctionAddress));

				for (SIZE_T i = 0; i < StringLengthA((LPCSTR)ForwarderName); i++)
				{

					if (((PCHAR)ForwarderName)[i] == '.')
					{
						DotOffset = i;
						ForwarderName[i] = 0;
						break;
					}

				}

				FunctionMod	 = ForwarderName;
				FunctionName = ForwarderName + DotOffset + 1;

				DllModuleBase	= NativeLoadLibrary(FunctionMod, Win32);
				FunctionAddress = ResolveHashedFunction(Win32, DllModuleBase, djb2A(FunctionName));

			}

			return FunctionAddress;

		}

	}

	return NULL;

}

BOOL ResolveIAT
(
	_In_ PVOID ImageBase,
	_In_ PIMAGE_DATA_DIRECTORY IatRva,
	_In_ pWin32 Win32
)
{

	NTSTATUS					Status						= STATUS_SUCCESS;

	PIMAGE_THUNK_DATA			pOriginalThunkData			= NULL;
	PIMAGE_THUNK_DATA			pFirstThunkData				= NULL;

	PIMAGE_IMPORT_DESCRIPTOR	pImageImportDescriptor		= NULL;
	PIMAGE_IMPORT_BY_NAME		pImageImportByName			= NULL;

	PCHAR						ImportModuleName			= NULL;
	HMODULE						ImportModule				= NULL;

	PVOID						Function					= NULL;
	LPVOID						ImportAddressTableDirectory = NULL;

	ANSI_STRING					AnsiString					= { 0 };


	ImportAddressTableDirectory = C_PTR(U_PTR(ImageBase) + IatRva->VirtualAddress);

	for (pImageImportDescriptor = ImportAddressTableDirectory; pImageImportDescriptor->Name != 0; ++pImageImportDescriptor)
	{

		pOriginalThunkData	= (PIMAGE_THUNK_DATA)(U_PTR(ImageBase) + pImageImportDescriptor->OriginalFirstThunk);
		pFirstThunkData		= (PIMAGE_THUNK_DATA)(U_PTR(ImageBase) + pImageImportDescriptor->FirstThunk);
		ImportModuleName	= (PCHAR)(U_PTR(ImageBase) + pImageImportDescriptor->Name);

		if (!(ImportModule = NativeLoadLibrary(ImportModuleName, Win32)))
		{
			return FALSE;
		}

		for (; pOriginalThunkData->u1.AddressOfData != 0; ++pOriginalThunkData, ++pFirstThunkData)
		{

			if (pOriginalThunkData->u1.Function == 0 && pFirstThunkData->u1.Function == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunkData->u1.Ordinal))
			{

				if (!NT_SUCCESS(Status = Win32->Api.LdrGetProcedureAddress(ImportModule, NULL, IMAGE_ORDINAL(pOriginalThunkData->u1.Ordinal), &Function)))
				{
					return FALSE;
				}

				if (Function != NULL)
					pFirstThunkData->u1.Function = (ULONGLONG)Function;

			}
			else
			{

				pImageImportByName = C_PTR(U_PTR(ImageBase) + pOriginalThunkData->u1.AddressOfData);

				AnsiString.Length		 = StringLengthA(pImageImportByName->Name);
				AnsiString.MaximumLength = AnsiString.Length;
				AnsiString.Buffer		 = pImageImportByName->Name;

				if (!NT_SUCCESS(Status = Win32->Api.LdrGetProcedureAddress(ImportModule, &AnsiString, 0, &Function)))
				{
					return FALSE;
				}

				if (Function != NULL)
					pFirstThunkData->u1.Function = (ULONGLONG)Function;

			}

		}

	}

	return TRUE;

}

BOOL RelocSections
(
	_In_ DWORD RVA,
	_In_ PVOID ImageBase,
	_In_ DWORD_PTR Delta
)
{

	PIMAGE_BASE_RELOCATION	Reloc		= NULL;
	PBASE_RELOCATION_ENTRY	RelocEntry	= NULL;
	DWORD					Size		= 0;

	if (RVA)
	{
		Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)ImageBase + RVA);

		while (Reloc->VirtualAddress)
		{

			Size = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			RelocEntry = (PBASE_RELOCATION_ENTRY)(Reloc + 1);

			for (DWORD i = 0; i < Size; i++)
			{

				if (RelocEntry[i].Type == IMAGE_REL_BASED_DIR64)
				{
					ULONGLONG* PatchedAddress = (ULONGLONG*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += (ULONGLONG)Delta;
				}

				else if (RelocEntry[i].Type == IMAGE_REL_BASED_HIGHLOW)
				{
					DWORD* PatchedAddress = (DWORD*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += (DWORD)Delta;
				}

				else if (RelocEntry[i].Type == IMAGE_REL_BASED_HIGH)
				{
					WORD* PatchedAddress = (WORD*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += HIWORD(Delta);
				}

				else if (RelocEntry[i].Type == IMAGE_REL_BASED_LOW)
				{
					WORD* PatchedAddress = (WORD*)((PBYTE)ImageBase + Reloc->VirtualAddress + RelocEntry[i].Offset);
					*PatchedAddress += LOWORD(Delta);
				}

				else if (RelocEntry[i].Type == IMAGE_REL_BASED_ABSOLUTE)
				{
					break;
				}

			}
			Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)Reloc + Reloc->SizeOfBlock);

		}

	}

	return TRUE;

}


BOOL ChangeMemoryProtection
(
	_In_ PVOID TargetBaseAddress,
	_In_ PIMAGE_NT_HEADERS pImgNt,
	_In_ pWin32 Win32
)
{

	PIMAGE_SECTION_HEADER pImgSec = IMAGE_FIRST_SECTION(pImgNt);

	for (int i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{

		ULONG ulProtection = 0;
		ULONG ulOldProt = 0;

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

		PVOID BaseAddress = C_PTR((U_PTR(TargetBaseAddress) + pImgSec[i].VirtualAddress));
		SIZE_T Size = pImgSec[i].SizeOfRawData;

		if (!NT_SUCCESS(Win32->Api.NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &Size, ulProtection, &ulOldProt)))
		{
			return FALSE;
		}

	}

	return TRUE;

}