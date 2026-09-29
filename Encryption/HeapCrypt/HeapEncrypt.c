#include "HeapCrypt.h"

BOOLEAN HeapCrypt(void);

VOID My_Sleep(DWORD dwMilliseconds)
{
	SuspendThreads();

	INFO("Encrypting...");
	HeapCrypt();

	Sleep(dwMilliseconds);

	INFO("Decrypting...");
	HeapCrypt();

	ResumeThreads();
}

VOID RC4
(
	_In_ PVOID PayloadAddress,
	_In_ SIZE_T PayloadSize
)
{

	BYTE Rc4Key[16]		= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 }; // I'm lazy, you could just use rand
	USTRING Key			= { .Buffer = (PUCHAR)&Rc4Key };			Key.Length	= Key.MaximumLength		= sizeof(Rc4Key);
	USTRING Data		= { .Buffer = (PUCHAR)PayloadAddress };		Data.Length = Data.MaximumLength	= PayloadSize;

	

	LOADAPI(_SystemFunction033, SystemFunction033, L"Advapi32.dll");

	SystemFunction033(&Data, &Key);

}

BOOLEAN SuspendThreads(void)
{

	HANDLE			SnapHandle		= NULL;
	HANDLE			ThreadHandle	= NULL;
	THREADENTRY32	te32			= { 0 };

	RtlSecureZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	if ((SnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId())) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE;
	}

	if (!Thread32First(SnapHandle, &te32))
	{
		PRINT_ERROR("Thread32First");
		return FALSE;
	}

	do
	{

		if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
		{
			if (!(ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID)))
			{
				PRINT_ERROR("OpenThread");
				return FALSE;
			}

			SuspendThread(ThreadHandle);
		}

	} while (Thread32Next(SnapHandle, &te32));

	return TRUE;

}

BOOLEAN ResumeThreads(void)
{

	HANDLE			SnapHandle		= NULL;
	HANDLE			ThreadHandle	= NULL;
	THREADENTRY32	te32			= { 0 };

	RtlSecureZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	if ((SnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId())) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE;
	}

	if (!Thread32First(SnapHandle, &te32))
	{
		PRINT_ERROR("Thread32First");
		return FALSE;
	}

	do
	{

		if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
		{
			if (!(ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID)))
			{
				PRINT_ERROR("OpenThread");
				return FALSE;
			}

			ResumeThread(ThreadHandle);
		}

	} while (Thread32Next(SnapHandle, &te32));

	return TRUE;

}

BOOLEAN HeapCrypt(void)
{

	PROCESS_HEAP_ENTRY	HeapEntry		= { 0 };
	DWORD				NumberOfHeaps	= GetProcessHeaps(0, NULL);;
	PHANDLE				HeapHandle		= NULL;

	if ((HeapHandle = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)NumberOfHeaps * sizeof(PVOID))) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	if (GetProcessHeaps(NumberOfHeaps, HeapHandle))
	{

		for (DWORD i = 0; i < NumberOfHeaps; i++)
		{

			if (HeapHandle[i] == GetProcessHeap())
				continue;

			RtlSecureZeroMemory(&HeapEntry, sizeof(PROCESS_HEAP_ENTRY));
			while (HeapWalk(HeapHandle[i], &HeapEntry))
			{

				if ((HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
				{
					RC4(HeapEntry.lpData, (SIZE_T)HeapEntry.cbData);
				}

			}

		}
		HeapFree(GetProcessHeap(), 0, HeapHandle);

	}


	return TRUE;

}