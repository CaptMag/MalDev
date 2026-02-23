#include "box.h"

PVOID GetModHandleWW
(
	IN wchar_t* target
)
{

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;

	for (PLIST_ENTRY pList = head->Flink; pList != head; pList = pList->Flink)
	{

		PLDR_DATA_TABLE_ENTRY ModuleDll =
			CONTAINING_RECORD(
				pList,
				LDR_DATA_TABLE_ENTRY,
				InLoadOrderLinks
			);

		if (_wcsicmp(ModuleDll->BaseDllName.Buffer, target) == 0)
		{
			return ModuleDll->DllBase;
		}
	}


	return;
}

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
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddress + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
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

BOOL FixIAT
(
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN PBYTE dllBase
)
{
	HMODULE k32 = GetModHandleWW(L"Kernel32.dll");
	if (!k32)
		return FALSE;

	DWORD LoadLibHash = sdbmrol16("LoadLibraryA");
	fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetHashAddress(k32, LoadLibHash);
	if (!pLoadLibraryA)
		return FALSE;

	DWORD GetProcHash = sdbmrol16("GetProcAddress");
	fnGetProcAddress pGetProcAddress = (fnGetProcAddress)GetHashAddress(k32, GetProcHash);
	if (!pGetProcAddress)
		return FALSE;

	if (pImgDataDir->Size > 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dllBase + pImgDataDir->VirtualAddress);

		for (SIZE_T i = 0; i < pImgDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pImgDataDir->VirtualAddress + dllBase + i);

			if (pImportDesc->OriginalFirstThunk == NULL && pImportDesc->FirstThunk == NULL)
				break;

			LPSTR cDllName = (LPSTR)(dllBase + pImportDesc->Name);
			HMODULE hModule = pLoadLibraryA(cDllName);

			if (!hModule)
				return FALSE;

			ULONG_PTR uOriginalFirstThunkRVA = pImportDesc->OriginalFirstThunk;
			ULONG_PTR uFirstThunkRVA = pImportDesc->FirstThunk;
			SIZE_T ImgThunkSize = 0;

			while (TRUE)
			{
				PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(dllBase + uOriginalFirstThunkRVA + ImgThunkSize);
				PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(dllBase + uFirstThunkRVA + ImgThunkSize);

				if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
					break;

				FARPROC pfnImportedFunc;

				if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
				{
					pfnImportedFunc = pGetProcAddress(hModule, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(dllBase + pOriginalFirstThunk->u1.AddressOfData);
					pfnImportedFunc = pGetProcAddress(hModule, pImportByName->Name);
				}

				pFirstThunk->u1.Function = (ULONG_PTR)pfnImportedFunc;
				ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
			}
		}
	}

	return TRUE;
}