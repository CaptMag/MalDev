#include "box.h"

BOOL ChangeProtection
(
	IN PVOID TargetBaseAddress,
	IN LPVOID lpFile
)
{

	PBYTE pBase = (PBYTE)lpFile;
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	PIMAGE_SECTION_HEADER pImgSec = IMAGE_FIRST_SECTION(pImgNt);

	for (int i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{

		DWORD dwProtection = 0;
		DWORD dwOldProt = 0;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if ((pImgSec[i].Characteristics & IMAGE_SCN_MEM_READ) && (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_READWRITE;

		if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (pImgSec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtection = PAGE_EXECUTE_READWRITE;
			else
				dwProtection = PAGE_EXECUTE_READ;
		}

		PVOID BaseAddress = (PVOID)((PBYTE)TargetBaseAddress + pImgSec[i].VirtualAddress);
		SIZE_T Size = pImgSec[i].SizeOfRawData;

		if (!VirtualProtect(BaseAddress, Size, dwProtection, &dwOldProt))
		{
			WARN("Failed To Change Memory Protection!");
			PRINT_ERROR("VirtualProtect");
			return FALSE;
		}

		INFO("Current Protection --> [%ld]", dwProtection);

	}

}