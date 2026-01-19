#include "box.h"

BOOL ReadTargetFile
(
	OUT PVOID* NtdllBuf
)

{

	HANDLE hFile = NULL;
	BOOL State = TRUE;
	DWORD NumberOfBytesToRead = NULL;
	LPVOID lppBuffer = NULL;
	NTSTATUS status = NULL;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb = { 0 };

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}
	INFO("[0x%p] Current Ntdll Handle", ntdll);

	RtlInitUnicodeString g_RtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");

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

	NtCreateFile fn_NtCreateFile = (NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
	NtQueryInformationFile fn_NtQueryInformationFile = (NtQueryInformationFile)GetProcAddress(ntdll, "NtQueryInformationFile");
	NtReadFile fn_NtReadFile = (NtReadFile)GetProcAddress(ntdll, "NtReadFile");


	status = fn_NtCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &OA, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT), NULL, 0);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtCreateFile");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current File Handle", hFile);

	status = fn_NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtQueryInformationFile");
		State = FALSE; goto CLEANUP;
	}

	SIZE_T fileSize = (SIZE_T)fsi.EndOfFile.QuadPart;
	INFO("[%ld] Current File Size", fileSize);


	if ((lppBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize)) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Allocated Bytes to Buffer", fileSize);

	status = fn_NtReadFile(hFile, NULL, NULL, NULL, &iosb, lppBuffer, fileSize, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtReadFile");
		State = FALSE; goto CLEANUP;
	}

	SIZE_T bytesRead = iosb.Information;

	OKAY("[%zu] Successfully Read File!", fileSize);

	*NtdllBuf = lppBuffer;

CLEANUP:

	return State;

}

BOOL CheckHeaders
(
	IN PVOID* NtdllBuf,
	IN HMODULE NtdllHandle,
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
	INFO("[Read] ImageBase:   [0x%p]", NtdllBuf);

	INFO("[Loaded] SizeOfImage: [0x%X]", pImgNt->OptionalHeader.SizeOfImage);
	INFO("[Read] SizeOfImage:   [0x%X]", pImgNt2->OptionalHeader.SizeOfImage);

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