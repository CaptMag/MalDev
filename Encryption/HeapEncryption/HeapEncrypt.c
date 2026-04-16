#include "box.h"

// https://labs.cognisys.group/posts/Advanced-Module-Stomping-and-Heap-Stack-Encryption/
// https://stackoverflow.com/questions/5720326/suspending-and-resuming-threads-in-c

BYTE _key[] = { 0xDE, 0xAD, 0xBE, 0xEF };

BOOL Rc4
(
	IN PBYTE Buffer,
	IN SIZE_T BufferSize
)
{

	NTSTATUS		STATUS = NULL;

	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof(_key);

	data.Buffer = (PUCHAR)Buffer;
	data.Length = BufferSize;

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&data, &key)) != 0x0)
	{
		PRINT_ERROR("SystemFunction033");
		return FALSE;
	}

	return TRUE;
}

BOOL SleepThreads
(
	IN DWORD TID
)
{

	HANDLE hSnap = 0, hThread = 0;

	THREADENTRY32 te32;
	RtlSecureZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Create New Snapshot");
		PRINT_ERROR("CreateToolHelp32Snapshot");
		return FALSE;
	}

	if (!Thread32First(hSnap, &te32))
		return FALSE;

	do
	{
	
		if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != TID)
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);
		}

	} while (Thread32Next(hSnap, &te32));

	CloseHandle(hSnap);
	return TRUE;

}

BOOL ResumeThreads
(
	IN DWORD TID
)
{

	HANDLE hSnap = 0, hThread = 0;

	THREADENTRY32 te32;
	RtlSecureZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Create New Snapshot");
		PRINT_ERROR("CreateToolHelp32Snapshot");
		return FALSE;
	}

	if (!Thread32First(hSnap, &te32))
		return FALSE;

	do
	{

		if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != TID)
		{
			hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}

	} while (Thread32Next(hSnap, &te32));

	CloseHandle(hSnap);
	return TRUE;

}

BOOL HeapEncrypt()
{

	PROCESS_HEAP_ENTRY pHeapEntry = { 0 };
	PHANDLE hHeaps = 0;
	DWORD NumberOfHeaps = 0;

	NumberOfHeaps = GetProcessHeaps(0, NULL); // Initialization
	hHeaps = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HANDLE) * NumberOfHeaps);
	GetProcessHeaps(NumberOfHeaps, hHeaps);

	for (INT i = 0; i < NumberOfHeaps; i++)
	{

		if (hHeaps[i] == GetProcessHeap())
			continue;

		RtlSecureZeroMemory(&pHeapEntry, sizeof(PROCESS_HEAP_ENTRY));

		while (HeapWalk(hHeaps[i], &pHeapEntry))
		{

			if ((pHeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
			{

				Rc4((PBYTE)pHeapEntry.lpData, pHeapEntry.cbData);

			}

		}
	}

	HeapFree(GetProcessHeap(), 0, hHeaps);
	return TRUE;

}

BOOL HeapSleep
(
	DWORD SleepTime
)
{

	DWORD TID = GetCurrentThreadId();

	if (!SleepThreads(TID))
	{
		WARN("Failed To Suspend Running Threads!");
		PRINT_ERROR("SleepThreads");
		return FALSE;
	}

	INFO("Sleeping Threads!");

	if (!HeapEncrypt())
	{
		WARN("Failed To Encrypt Heap!");
		PRINT_ERROR("HeapEncrypt");
		return FALSE;
	}

	INFO("Encrypting Heap!");

	Sleep(SleepTime);

	OKAY("Sleeping for %ld miliseconds", SleepTime);

	if (!HeapEncrypt())
	{
		WARN("Failed To Decrypt Heap!");
		PRINT_ERROR("HeapDecrypt");
		return FALSE;
	}

	INFO("Decrypting Heap!");

	if (!ResumeThreads(TID))
	{
		WARN("Failed To Suspend Running Threads!");
		PRINT_ERROR("SleepThreads");
		return FALSE;
	}

	INFO("Resuming Threads!");

	OKAY("DONE!");

	return TRUE;
}