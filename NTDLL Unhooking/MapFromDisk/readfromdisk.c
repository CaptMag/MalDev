#include "box.h"

// https://www.jeremyong.com/winapi/io/2024/11/03/windows-memory-mapped-file-io/

BOOL ReadNtdll
(
	OUT PVOID* NtdllBuf
)

{

	BOOL		State				= TRUE;
	HANDLE		hFile				= NULL, 
				hSection			= NULL;
	DWORD		FileSize			= 0, 
				dwNumofBytesRead	= 0;
	PVOID		BaseAddress			= NULL;
	SIZE_T		ViewSize			= 0;
	NTSTATUS	status				= NULL;
	IO_STATUS_BLOCK ISB				= { 0 };

	HMODULE NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NtdllHandle == NULL)
	{
		PRINT_ERROR("GetModuleHandleW");
		State = FALSE;
	}

	INFO("[0x%p] Loaded ntdll.dll Base Address", NtdllHandle);

	RtlInitUnicodeString g_RtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(NtdllHandle, "RtlInitUnicodeString");

	UNICODE_STRING usPath;
	g_RtlInitUnicodeString(&usPath, L"\\??\\C:\\Windows\\System32\\ntdll.dll");

	INFO("Current Path: %wZ", &usPath);

	OBJECT_ATTRIBUTES OA;
	InitializeObjectAttributes(
		&OA,
		&usPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	INFO("[0x%p] Current Object Attribute Handle", OA);
	
	NtCreateFile g_NtCreateFile = (NtCreateFile)GetProcAddress(NtdllHandle, "NtCreateFile");
	NtCreateSection g_NtCreateSection = (NtCreateSection)GetProcAddress(NtdllHandle, "NtCreateSection");
	NtMapViewOfSection g_NtMapViewOfSection = (NtMapViewOfSection)GetProcAddress(NtdllHandle, "NtMapViewOfSection");

	status = g_NtCreateFile(&hFile, FILE_GENERIC_READ, &OA, &ISB, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtCreateFile");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Successfully Opened Ntdll.dll!");

	status = g_NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtCreateSection");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Section Created!", hSection);

	status = g_NtMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, 1, 0, PAGE_READONLY);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtMapViewOfSection");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Section Mapped Using Allocation Page_ReadOnly!");
	INFO("[0x%p] Current Base Address with newly loaded Ntdll.dll", BaseAddress);

	*NtdllBuf = BaseAddress;

CLEANUP:

	if (hFile)
		CloseHandle(hFile);

	if (hSection)
		CloseHandle(hSection);

	return State;

}

BOOL CheckHeaders
(
	IN HMODULE NtdllHandle,
	IN PVOID NtdllBuf,
	OUT PVOID* pHookedNtdllTxt,
	OUT PVOID* pUnhookedNtdllTxt,
	OUT SIZE_T* pNtdllTxtSize
)

{
	PVOID HookedNtdllTxt, UnhookedNtdllTxt = NULL;
	SIZE_T NtdllTxtSize = NULL;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)NtdllHandle;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Image Dos Headers");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((PBYTE)NtdllHandle + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Image Nt Headers");
		return FALSE;
	}

	PIMAGE_DOS_HEADER pImgDos2 = (PIMAGE_DOS_HEADER)NtdllBuf;
	if (pImgDos2->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Image Dos Headers");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNt2 = (PIMAGE_NT_HEADERS)((PBYTE)NtdllBuf + pImgDos2->e_lfanew);
	if (pImgNt2->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Image Nt Headers");
		return FALSE;
	}

	INFO("[Loaded] ImageBase: [0x%p]", NtdllHandle);
	INFO("[Mapped] ImageBase: [0x%p]", NtdllBuf);

	INFO("[Mapped] SizeOfImage: [0x%X]", pImgNt2->OptionalHeader.SizeOfImage);
	INFO("[Loaded] SizeOfImage: [0x%X]", pImgNt->OptionalHeader.SizeOfImage);

	if (!(pImgNt2->OptionalHeader.SizeOfImage == pImgNt->OptionalHeader.SizeOfImage))
	{
		WARN("SizeOfImage Not Matching! Mapped Ntdll Likely Corrupted!");
		return FALSE;
	}

	OKAY("SizeOfImage Matched! Properly Mapped Ntdll");

	HookedNtdllTxt = (PVOID)(pImgNt->OptionalHeader.BaseOfCode + (ULONG_PTR)NtdllHandle);
	UnhookedNtdllTxt = (PVOID)(pImgNt2->OptionalHeader.BaseOfCode + (ULONG_PTR)NtdllBuf);
	NtdllTxtSize = pImgNt->OptionalHeader.SizeOfCode;

	printf(
		"[0x%p] Hooked Ntdll Text Section Address\n"
		"[0x%p] Unhooked Ntdll Text Section Address\n"
		"[0x%p] Text Section Size\n",
		HookedNtdllTxt, UnhookedNtdllTxt, NtdllTxtSize
	);

	*pHookedNtdllTxt = HookedNtdllTxt;
	*pUnhookedNtdllTxt = UnhookedNtdllTxt;
	*pNtdllTxtSize = NtdllTxtSize;

	return TRUE;

}