#include "NtPeInjection.h"

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ LPVOID* lpBuffer
)
{

	HANDLE	hFile				= NULL;
	BOOL	State				= TRUE;
	DWORD	lpNumberOfBytesRead = 0;
	DWORD	NumberOfBytesRead	= 0;

	if (!PeName || !lpBuffer)
		return FALSE;

	if (!(hFile = CreateFileW(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) || hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Current File Handle", hFile);

	if (!(NumberOfBytesRead = GetFileSize(hFile, NULL)) || NumberOfBytesRead == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Current File Size", NumberOfBytesRead);

	if (!(*lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytesRead)) || *lpBuffer == NULL)
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
	ULONG						Size			= strlen(ModuleName);
	UNICODE_STRING				uString			= { 0 };
	PVOID						pModule			= NULL;

	// convert to wchar
	if (!NT_SUCCESS(Status = Win32->Api.RtlMultiByteToUnicodeN(ModuleW, sizeof(ModuleW), &Size, ModuleName, strlen(ModuleName) + 1)))
	{
		NTERROR("RtlMultiByteToUnicodeN");
		return NULL;
	}

	// thanks to KaynLdr :)
	if (ModuleW)
	{

		USHORT DestSize			= wcslen(ModuleW) * sizeof(WCHAR);
		uString.Length			= DestSize;
		uString.MaximumLength	= DestSize + sizeof(WCHAR);

	}

	uString.Buffer = ModuleW;

	if (!NT_SUCCESS(Status = Win32->Api.LdrLoadDll(NULL, 0, &uString, &pModule)))
		return NULL;

	return pModule;

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

		pOriginalThunkData	= C_PTR(U_PTR(ImageBase) + pImageImportDescriptor->OriginalFirstThunk);
		pFirstThunkData		= C_PTR(U_PTR(ImageBase) + pImageImportDescriptor->FirstThunk);
		ImportModuleName	= C_PTR(U_PTR(ImageBase) + pImageImportDescriptor->Name);

		if (!(ImportModule = NativeLoadLibrary(ImportModuleName, Win32)))
		{
			PRINT_ERROR("NativeLoadLibrary");
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
					NTERROR("LdrGetProcedureAddress");
					return FALSE;
				}

				if (Function != NULL)
					pFirstThunkData->u1.Function = (ULONGLONG)Function;

			}
			else
			{

				pImageImportByName			= C_PTR(U_PTR(ImageBase) + pOriginalThunkData->u1.AddressOfData);

				AnsiString.Length			= strlen(pImageImportByName->Name);
				AnsiString.MaximumLength	= AnsiString.Length;
				AnsiString.Buffer			= pImageImportByName->Name;

				if (!NT_SUCCESS(Status = Win32->Api.LdrGetProcedureAddress(ImportModule, &AnsiString, 0, &Function)))
				{
					NTERROR("LdrGetProcesureAddress2");
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

	NTSTATUS			  Status  = STATUS_SUCCESS;
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

		if (!NT_SUCCESS(Status = Win32->Api.NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &Size, ulProtection, &ulOldProt)))
		{
			NTERROR("NtProtectVirtualMemory");
			return FALSE;
		}

	}

	return TRUE;

}

BOOLEAN NtPeInjection
(
	_In_ LPVOID TargetPayloadBuffer
)
{

	NTSTATUS				Status					= STATUS_SUCCESS;
	PIMAGE_NT_HEADERS64		pImageNtHeader			= NULL;
	DWORD_PTR				Delta					= 0;
	PVOID					ImageBase				= NULL;
	PVOID					EntryPoint				= NULL;
	MAIN					pMain					= NULL;
	Win32					PortableExecutableApi	= { 0 };
	DWORD					RelocRva				= 0;


	pImageNtHeader = (PIMAGE_NT_HEADERS64)(U_PTR(TargetPayloadBuffer) + ((PIMAGE_DOS_HEADER)TargetPayloadBuffer)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		WARN("Nt Signatures do not match!");
		return FALSE;
	}

	PortableExecutableApi.Module.Ntdll					= GetModuleHandleW(L"Ntdll.dll");

	PortableExecutableApi.Api.NtFlushInstructionCache	= (fnNtFlushInstructionCache)GetProcAddress(PortableExecutableApi.Module.Ntdll, "NtFlushInstructionCache");
	PortableExecutableApi.Api.NtAllocateVirtualMemory	= (fnNtAllocateVirtualMemory)GetProcAddress(PortableExecutableApi.Module.Ntdll, "NtAllocateVirtualMemory");
	PortableExecutableApi.Api.NtProtectVirtualMemory	= (fnNtProtectVirtualMemory)GetProcAddress(PortableExecutableApi.Module.Ntdll, "NtProtectVirtualMemory");
	PortableExecutableApi.Api.LdrGetProcedureAddress	= (fnLdrGetProcedureAddress)GetProcAddress(PortableExecutableApi.Module.Ntdll, "LdrGetProcedureAddress");
	PortableExecutableApi.Api.RtlMultiByteToUnicodeN	= (fnRtlMultiByteToUnicodeN)GetProcAddress(PortableExecutableApi.Module.Ntdll, "RtlMultiByteToUnicodeN");
	PortableExecutableApi.Api.LdrLoadDll				= (fnLdrLoadDll)GetProcAddress(PortableExecutableApi.Module.Ntdll, "LdrLoadDll");

	PortableExecutableApi.PeHeaders.pImgNtHdrs				= pImageNtHeader;
	PortableExecutableApi.PeHeaders.pImgSecHdr				= IMAGE_FIRST_SECTION(PortableExecutableApi.PeHeaders.pImgNtHdrs);

	PortableExecutableApi.PeHeaders.pEntryImportDataDir		= &PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PortableExecutableApi.PeHeaders.pEntryExportDataDir		= &PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PortableExecutableApi.PeHeaders.pEntryBaseRelocDataDir	= &PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PortableExecutableApi.PeHeaders.pEntryExceptionDataDir	= &PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PortableExecutableApi.PeHeaders.pEntryTLSDataDir		= &PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	SIZE_T RegionSize = PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage;

	if (!NT_SUCCESS(Status = PortableExecutableApi.Api.NtAllocateVirtualMemory(NtCurrentProcess(), &ImageBase, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
	{
		NTERROR("NtAllocateVirtualMemory");
		return FALSE;
	}

	INFO("[0x%p] Base Address", ImageBase);
	INFO("[%d] Size of Image", PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage);

	for (DWORD i = 0; i < PortableExecutableApi.PeHeaders.pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{

		if (PortableExecutableApi.PeHeaders.pImgSecHdr[i].SizeOfRawData == 0)
			continue;

		memcpy
		(
			C_PTR((U_PTR(ImageBase) + PortableExecutableApi.PeHeaders.pImgSecHdr[i].VirtualAddress)),
			C_PTR((U_PTR(TargetPayloadBuffer) + PortableExecutableApi.PeHeaders.pImgSecHdr[i].PointerToRawData)),
			PortableExecutableApi.PeHeaders.pImgSecHdr[i].SizeOfRawData
		);

	}

	Delta = (U_PTR(ImageBase) - PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.ImageBase);
	RelocRva = PortableExecutableApi.PeHeaders.pEntryBaseRelocDataDir->VirtualAddress;

	if (!ResolveIAT(ImageBase, PortableExecutableApi.PeHeaders.pEntryImportDataDir, &PortableExecutableApi))
	{
		PRINT_ERROR("ResolveIAT");
		return FALSE;
	}

	INFO("Import Address/Lookup Table Resolved Successfully!");

	if (!RelocSections(RelocRva, ImageBase, Delta))
	{
		PRINT_ERROR("RelocSections");
		return FALSE;
	}

	INFO("Address Relocations Successfull!");

	if (!ChangeMemoryProtection(ImageBase, PortableExecutableApi.PeHeaders.pImgNtHdrs, &PortableExecutableApi))
	{
		PRINT_ERROR("ChangeMemoryProtection");
		return FALSE;
	}

	INFO("Memory Protections Changed!");

	EntryPoint = C_PTR((U_PTR(ImageBase) + PortableExecutableApi.PeHeaders.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));
	if (!EntryPoint)
		return FALSE;

	INFO("[0x%p] Entry Point", EntryPoint);

	pMain = (MAIN)EntryPoint;
	return pMain();

}