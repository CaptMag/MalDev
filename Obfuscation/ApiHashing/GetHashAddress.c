#include "box.h"

DWORD sdbmrol16
(
	IN PCHAR String
)
{

	UINT hash = 0;
	UINT StringLen = strlen(String);

	for (UINT i = 0; i < StringLen; i++)
	{
		hash = (hash << 16) | (hash >> (32 - 16)); // move left by 16
		hash = (toupper(String[i])) + (hash << 6) + (hash << 16) - hash; // sdbm
		hash = hash ^ i; // xor
	}

	INFO("string: %s | hash: %u", String, hash);
	return hash;

}

PVOID GetHashAddress
(
	IN PVOID BaseAddress,
	IN DWORD ApiHash
)

{

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("pImgDos");
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("pImgNt");
		return NULL;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = (PIMAGE_OPTIONAL_HEADER)&pImgNt->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseAddress + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)BaseAddress + pImgExport->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExport->NumberOfNames; i++)
	{


		CHAR* FuncName = (CHAR*)BaseAddress + Name[i];

		if (ApiHash != sdbmrol16(FuncName))
			continue;
		WORD ord = Ordinal[i];
		PVOID FuncAddr = (LPBYTE)BaseAddress + Address[ord];
		return FuncAddr;
	}

	return NULL;

}
