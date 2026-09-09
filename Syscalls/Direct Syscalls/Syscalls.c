#include "Syscalls.h"

DWORD djb2W(PWSTR str, SIZE_T length)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = (PUCHAR)str;

	do
	{
		UCHAR Char = *Ptr;

		if (!length)
		{
			if (!*Ptr)
				break;
		}
		else
		{
			if ((ULONG)(Ptr - (PUCHAR)str) >= length)
				break;

			if (!*Ptr)
				Ptr++;
		}

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	return hash;
}

DWORD djb2A(char* str)
{
	DWORD	hash = 5381;
	PUCHAR	Ptr = str;

	do
	{

		UCHAR Char = *Ptr;

		if (!*Ptr) break;

		if (!*Ptr)
			Ptr++;

		if (Char >= 'a')
			Char -= 0x20;

		hash = ((hash << 5) + hash) + Char;
		++Ptr;

	} while (TRUE);

	return hash;
}

PVOID LoadDllModule
(
	_In_ DWORD DllModuleHash
)
{

	PPEB					pPeb		= (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)pPeb->Ldr;
	PLIST_ENTRY				Head		= &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY				pList		= Head->Flink;
	PLDR_DATA_TABLE_ENTRY	pDataLdr	= NULL;

	for (pList; pList != Head; pList = pList->Flink)
	{

		pDataLdr = (PLDR_DATA_TABLE_ENTRY)pList;

		if (djb2W(pDataLdr->BaseDllName.Buffer, pDataLdr->BaseDllName.Length) == DllModuleHash)
			return pDataLdr->DllBase;

	}

	return NULL;

}

BOOLEAN FetchSyscalls
(
	_In_ PVOID FunctionAddress,
	_In_ pSyscallInfo DllConfig
)
{

	for (DWORD x = 0; x < SEARCH_RANGE; x++)
	{

		if (*((PBYTE)FunctionAddress + x * DOWN) == 0x4c
			&& *((PBYTE)FunctionAddress + 1 + x * DOWN) == 0x8b
			&& *((PBYTE)FunctionAddress + 2 + x * DOWN) == 0xd1
			&& *((PBYTE)FunctionAddress + 3 + x * DOWN) == 0xb8
			&& *((PBYTE)FunctionAddress + 6 + x * DOWN) == 0x00
			&& *((PBYTE)FunctionAddress + 7 + x * DOWN) == 0x00)
		{

			BYTE high = *((PBYTE)FunctionAddress + x * DOWN + 5);
			BYTE low  = *((PBYTE)FunctionAddress + x * DOWN + 4);

			DllConfig->SyscallInfo.SyscallNumber = (high << 8) | low + x;
			PBYTE StubDown = (PBYTE)FunctionAddress + x * DOWN;

			for (DWORD i = 0; i < 32; i++)
			{

				if (*((PBYTE)StubDown + i) == 0x0F && *((PBYTE)StubDown + i + 1) == 0x05)
				{

					DllConfig->SyscallInfo.SyscallInstruction = C_PTR((INT_PTR)StubDown + i);
					break;

				}

			}
			return TRUE;

		}

		if (*((PBYTE)FunctionAddress + x * UP) == 0x4c
			&& *((PBYTE)FunctionAddress + 1 + x * UP) == 0x8b
			&& *((PBYTE)FunctionAddress + 2 + x * UP) == 0xd1
			&& *((PBYTE)FunctionAddress + 3 + x * UP) == 0xb8
			&& *((PBYTE)FunctionAddress + 6 + x * UP) == 0x00
			&& *((PBYTE)FunctionAddress + 7 + x * UP) == 0x00)
		{

			BYTE high = *((PBYTE)FunctionAddress + x * UP + 5);
			BYTE low  = *((PBYTE)FunctionAddress + x * UP + 4);

			DllConfig->SyscallInfo.SyscallNumber = (high << 8) | low - x;
			PBYTE StubUp = (PBYTE)FunctionAddress + x * UP;

			for (DWORD i = 0; i < 32; i++)
			{

				if (*((PBYTE)StubUp + i) == 0x0F && *((PBYTE)StubUp + i + 1) == 0x05)
				{

					DllConfig->SyscallInfo.SyscallInstruction = C_PTR((INT_PTR)StubUp + i);
					break;

				}

			}
			return TRUE;

		}

	}

	if (DllConfig->SyscallInfo.SyscallNumber == 0)
		return FALSE;

	return TRUE;

}

BOOLEAN InvokeSyscalls
(
	_In_ pSyscallInfo SyscallConfig,
	_In_ PVOID BaseAddress,
	_In_ DWORD ApiHash
)
{

	PIMAGE_NT_HEADERS64		pImageNtHeader			= NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory	= NULL;

	PVOID					FunctionAddress			= NULL;
	PCHAR					FunctionName			= NULL;

	PDWORD					AddressOfFunctions		= NULL;
	PDWORD					AddressOfNames			= NULL;
	PWORD					AddressOfNamesOrdinals	= NULL;


	pImageNtHeader = (PIMAGE_NT_HEADERS64)(U_PTR(BaseAddress) + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	if (!(pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(U_PTR(BaseAddress) + pImageNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress)) || pImageExportDirectory == NULL)
		return FALSE;

	AddressOfFunctions		= C_PTR(U_PTR(BaseAddress) + pImageExportDirectory->AddressOfFunctions);
	AddressOfNames			= C_PTR(U_PTR(BaseAddress) + pImageExportDirectory->AddressOfNames);
	AddressOfNamesOrdinals	= C_PTR(U_PTR(BaseAddress) + pImageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
	{

		FunctionName	= (PCHAR)(U_PTR(BaseAddress) + AddressOfNames[i]);
		FunctionAddress = C_PTR((U_PTR(BaseAddress) + AddressOfFunctions[AddressOfNamesOrdinals[i]]));

		if (ApiHash == djb2A(FunctionName))
		{

			if (!FetchSyscalls(FunctionAddress, SyscallConfig))
			{
				PRINT_ERROR("FetchSyscalls");
				return FALSE;
			}

			SyscallConfig->SyscallInfo.FunctionAddress = FunctionAddress;

			return TRUE;

		}

	}

	return FALSE;

}