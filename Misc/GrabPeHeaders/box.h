#include <windows.h>
#include <stdio.h>

#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

typedef struct _PEHEADERS {
	PIMAGE_NT_HEADERS64		pImgNt;					// pImgNt
	PIMAGE_SECTION_HEADER	pImgSecHeader;			// IMAGE_FIRST_SECTION(pImgNt)
	PIMAGE_DATA_DIRECTORY	pImgDataDir;			// pImgNt->OptionalHeader.DataDirectory
	PIMAGE_DATA_DIRECTORY	pImgDirEntryImport;		// [IMAGE_DIRECTORY_ENTRY_IMPORT]
	PIMAGE_DATA_DIRECTORY	pImgDirEntryBaseReloc;	// [IMAGE_DIRECTORY_ENTRY_BASERELOC]
	PIMAGE_DATA_DIRECTORY	pImgDirEntryTls;		// [IMAGE_DIRECTORY_ENTRY_TLS]
	PIMAGE_DATA_DIRECTORY	pImgDirEntryException;	// [IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	PIMAGE_DATA_DIRECTORY	pImgDirEntryExport;		// [IMAGE_DIRECTORY_ENTRY_EXPORT]
} PEHEADERS, *PPEHEADERS;