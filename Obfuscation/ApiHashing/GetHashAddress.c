#include "box.h"

#define FNV_OFFSET 2166136261u
#define FNV_PRIME  16777619u

#define DOWN 32
#define UP -32

DWORD GetBaseHash
(
	IN char* FuncName,
	IN PVOID Dllbase,
	IN PIMAGE_EXPORT_DIRECTORY pImgExport
)
{

	UINT_PTR base = (UINT_PTR)Dllbase;
	UINT_PTR export = (UINT_PTR)base + pImgExport->AddressOfNames;

	UINT32 seed = (UINT32)((export >> 3) ^ (export << 13));

	UINT32 hash = FNV_OFFSET;

	hash ^= seed;
	hash *= FNV_PRIME;

	while (*FuncName)
	{
		hash ^= (UINT8)*FuncName++;
		hash *= FNV_PRIME;
	}

	return hash;

}

PVOID GetHashAddress
(
	IN PIMAGE_EXPORT_DIRECTORY pImgDir,
	IN PVOID Ntdllbase,
	IN DWORD ApiHash
)

{

	PDWORD Address = (PDWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgDir->NumberOfNames; i++)
	{


		CHAR* FuncName = (CHAR*)Ntdllbase + Name[i];

		if (ApiHash != GetBaseHash(FuncName, Ntdllbase, pImgDir))
			continue;
		WORD ord = Ordinal[i];
		PVOID FuncAddr = (LPBYTE)Ntdllbase + Address[ord];
		return FuncAddr;
	}

	return NULL;

}
