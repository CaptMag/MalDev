#include "box.h"

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


	PeHeaders.pImgNt				= pImgNt64;
	PeHeaders.pImgSecHeader			= IMAGE_FIRST_SECTION(PeHeaders.pImgNt);
	PeHeaders.pImgDataDir			= PeHeaders.pImgNt->OptionalHeader.DataDirectory;
	PeHeaders.pImgDirEntryImport	= &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PeHeaders.pImgDirEntryBaseReloc = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PeHeaders.pImgDirEntryTls		= &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_TLS];
	PeHeaders.pImgDirEntryException = &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PeHeaders.pImgDirEntryExport	= &PeHeaders.pImgDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];

	return TRUE;

}