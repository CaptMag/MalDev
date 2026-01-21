#include "box.h"

#define INITIAL_SEED	7	

// Vx Underground API
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	//INFO("0x%08X", Hash);
	return Hash;
}

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))

PVOID GetHashAddress
(
	IN PVOID BaseAddress,
	IN DWORD ApiHashName
)

{

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("pImgDos");
		return NULL;
	}

	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("pImgNt");
		return NULL;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = (PIMAGE_OPTIONAL_HEADER)&pImgNt->OptionalHeader;

	PIMAGE_DATA_DIRECTORY pImgDataDir64 = &pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseAddress + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExport->NumberOfNames; i++)
	{


		CHAR* FuncName = (CHAR*)BaseAddress + Name[i];

		if (ApiHashName == HASHA(FuncName))
		{
			WORD ord = Ordinal[i];
			PVOID FuncAddr = (LPBYTE)BaseAddress + Address[ord];

			INFO("ApiHashName: %ld | FuncAddr: 0x%p", ApiHashName, FuncAddr);
			return FuncAddr;
		}

	}

	return;

}
