#include "box.h"

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