#include <Windows.h>
#include <stdio.h>
#include "Box.h"



FARPROC HiddenProcAddress
(
	IN HMODULE hModule,
	IN LPCSTR ApiName
)


{
	static BOOL printedInfo = FALSE;


	// https://github.com/xalicex/Get-DLL-and-Function-Addresses/blob/main/GetModGetProc.c

	/* pBase --> Represents the base address as we will being using it to get the RVA */

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		WARN("Could not Successfully Create a Variable to the Image Dos Header Magic Letters (MZ)");
		return NULL;
	}


	/* pImgDos->e_lfanew ---> Points to the start of a new Executable */
	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		WARN("Could not Successfully point to the NT Headers!");
		return NULL;
	}


	/* Optional Header is stored inside the NT headers, and is exactly the same as the older, COFF headers */
	IMAGE_OPTIONAL_HEADER pImgOpt = pImgNt->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pBase + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)pBase + pImgExport->AddressOfFunctions);

	//Get the function names array 
	PDWORD Name = (PDWORD)((LPBYTE)pBase + pImgExport->AddressOfNames);

	//get the Ordinal array
	PWORD Ordinal = (PWORD)((LPBYTE)pBase + pImgExport->AddressOfNameOrdinals);


	if (!printedInfo)
	{
		printf("\n==============================[PE INFORMATION]==============================\n");
		printf("IMAGE_DOS_HEADER:            [%lu]\n", pImgDos->e_magic);
		printf("IMAGE_NT_HEADER:             [%lu]\n", pImgNt->Signature);
		printf("IMAGE_EXPORT_DIRECTORY:      [0x%p]\n", pImgExport);
		printf("Address Of Names:            [0x%p]\n", Name);
		printf("Address Of Functions:        [0x%p]\n", Address);
		printf("Address Of Name Ordinals:    [0x%p]\n\n", Ordinal);

		printedInfo = TRUE;
	}


	//INFO("Trying to get the Address of %s", ApiName);
	DWORD ApiHash = HASHA(ApiName);


	for (DWORD i = 0; i < pImgExport->NumberOfFunctions; i++)
	{

		CHAR* pFuncName = (CHAR*)(pBase + Name[i]);

		PVOID pFuncAddress = (PVOID)(pBase + Address[Ordinal[i]]);

		if (ApiHash == HASHA(pFuncName))
		{
			//OKAY("FOUND API: -\t NAME: %s -\t ADDRESS: 0x%p -\t ORDINAL: %d\n", pFuncName, pFuncAddress, Ordinal[i]);
			INFO("Current ApiHash for %s: 0x%0.8X", pFuncName, ApiHash);
			return pFuncAddress;
		}

	}


	return NULL;

}