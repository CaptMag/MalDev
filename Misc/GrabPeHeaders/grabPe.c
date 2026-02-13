#include <windows.h>
#include <stdio.h>

#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

BOOL GrabPeHeader
(
	OUT PIMAGE_NT_HEADERS* pImgNt,
	OUT PIMAGE_SECTION_HEADER* pImgSecHeader,
	OUT PIMAGE_DATA_DIRECTORY* pImgDataDir,
	OUT PIMAGE_EXPORT_DIRECTORY* ppImgExpDir,
	IN  LPVOID lpFile
)

{

	PBYTE pBase = (PBYTE)lpFile;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNt64 = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt64->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
		return FALSE;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = &pImgNt64->OptionalHeader;

	PIMAGE_SECTION_HEADER pImgSecHead = IMAGE_FIRST_SECTION(pImgNt64);

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)lpFile + pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PIMAGE_DATA_DIRECTORY pImgDataDir64 = &pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	*pImgNt = pImgNt64;
	*pImgSecHeader = pImgSecHead;
	*ppImgExpDir = pImgExpDir;
	*pImgDataDir = pImgDataDir64;

	return TRUE;

}