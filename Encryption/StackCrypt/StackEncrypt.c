#include "Encrypt.h"

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

BOOLEAN ThreadCrypt
(
	_In_ HANDLE ThreadHandle
)
{

	NTSTATUS					Status		= STATUS_SUCCESS;

	PVOID						Teb			= NULL;
	PVOID						StackTop	= NULL;
	PVOID						StackBase	= NULL;

	PNT_TIB						Tib			= NULL;
	SIZE_T						BytesRead	= 0;
	THREAD_BASIC_INFORMATION	TBI			= { 0 };

	LOADAPI(fnNtQueryInformationThread, NtQueryInformationThread, L"Ntdll.dll");

	if (!NT_SUCCESS(Status = NtQueryInformationThread(ThreadHandle, (THREADINFOCLASS)0, &TBI, sizeof(TBI), NULL)))
	{
		NT_ERROR("NtQueryInformationThread");
		return FALSE;
	}

	if ((Tib = (PNT_TIB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NT_TIB))) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	Teb = TBI.TebBaseAddress;
	if (!ReadProcessMemory(GetCurrentProcess(), Teb, Tib, sizeof(NT_TIB), &BytesRead))
	{
		PRINT_ERROR("ReadProcessMemory");
		return FALSE;
	}

	StackTop	= Tib->StackLimit;
	StackBase	= Tib->StackBase;

	RC4(StackTop, (SIZE_T)StackBase - (SIZE_T)StackTop);

	HeapFree(GetProcessHeap(), 0, Tib);

	return TRUE;

}

BOOLEAN ThreadCryptSuspend(void)
{

	HANDLE			SnapHandle		= NULL;
	HANDLE			ThreadHandle	= NULL;

	THREADENTRY32	te32			= { 0 };
	te32.dwSize						= sizeof(THREADENTRY32);

	if ((SnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == NULL)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE;
	}

	if (!Thread32First(SnapHandle, &te32))
	{
		PRINT_ERROR("Thread32First");
		return FALSE;
	}

	INFO("Encrypting");
	do
	{

		if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
		{

			if ((ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID)) == NULL)
			{
				PRINT_ERROR("OpenThread");
				return FALSE;
			}

			SuspendThread(ThreadHandle);

			if (!ThreadCrypt(ThreadHandle))
			{
				PRINT_ERROR("ThreadCrypt");
				return FALSE;
			}

			

		}

	} while (Thread32Next(SnapHandle, &te32));

	return TRUE;

}

BOOLEAN ThreadCryptResume(void)
{

	HANDLE			SnapHandle		= NULL;
	HANDLE			ThreadHandle	= NULL;

	THREADENTRY32	te32			= { 0 };
	te32.dwSize						= sizeof(THREADENTRY32);

	if ((SnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == NULL)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE;
	}

	if (!Thread32First(SnapHandle, &te32))
	{
		PRINT_ERROR("Thread32First");
		return FALSE;
	}

	INFO("Decrypting");
	do
	{

		if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
		{

			if ((ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID)) == NULL)
			{
				PRINT_ERROR("OpenThread");
				return FALSE;
			}

			if (!ThreadCrypt(ThreadHandle))
			{
				PRINT_ERROR("ThreadCrypt");
				return FALSE;
			}

			ResumeThread(ThreadHandle);
			CloseHandle(ThreadHandle);

		}

	} while (Thread32Next(SnapHandle, &te32));

	return TRUE;

}