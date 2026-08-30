#include "HWBPEngine.h"

// Refrences: 
// https://r136a1.dev/2026/01/14/command-and-evade-turlas-kazuar-v3-loader/
// https://github.com/TheEnergyStory/PatchlessEtwAndAmsiBypass

int main()
{

	NTSTATUS Status = STATUS_SUCCESS;

	fnNtTraceControl	NtTraceControl		= (fnNtTraceControl)GetProcAddress(GetModuleHandleW(L"Ntdll.dll"), "NtTraceControl");
	fnEtwEventWrite		EtwEventWrite		= (fnEtwEventWrite)GetProcAddress(GetModuleHandleW(L"Ntdll.dll"), "EtwEventWrite");
	fnEtwEventWriteFull EtwEventWriteFull	= (fnEtwEventWriteFull)GetProcAddress(GetModuleHandleW(L"Ntdll.dll"), "EtwEventWriteFull");
	fnNtTraceEvent		NtTraceEvent		= (fnNtTraceEvent)GetProcAddress(GetModuleHandleW(L"Ntdll.dll"), "NtTraceEvent");

	PVOID Handler = NULL;

	if (!(Handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)InitializeHardwareBPEngine)))
	{
		PRINT_ERROR("AddVectoredExceptionHandler");
		return 1;
	}

	INFO("[0x%p] NtTraceControl Address", NtTraceControl);

	SetHardwareBreakpoint(NtTraceControl);

	INFO("[0x%p] EtwEventWrite Address", EtwEventWrite);

	SetHardwareBreakpoint(EtwEventWrite);

	INFO("[0x%p] EtwEventWriteFull Address", EtwEventWriteFull);

	SetHardwareBreakpoint(EtwEventWriteFull);

	INFO("[0x%p] NtTraceEvent Address", NtTraceEvent);

	SetHardwareBreakpoint(NtTraceEvent);

	// put some random values, and see what the status code ends up being

	if (!NT_SUCCESS(Status = NtTraceControl(0, NULL, 0, NULL, 0, NULL)))
	{
		NT_ERROR("NtTraceControl");
		return 1;
	}

	INFO("NtTraceControl Status: 0x%08X", Status);

	if (!NT_SUCCESS(Status = EtwEventWrite(0, NULL, 0, NULL)))
	{
		NT_ERROR("EtwEventWrite");
		return 1;
	}

	INFO("EtwEventWrite Status: 0x%08X", Status);

	if (!NT_SUCCESS(Status = EtwEventWriteFull(0, NULL, 0, NULL, NULL, 0, NULL)))
	{
		NT_ERROR("NtTraceControl");
		return 1;
	}

	INFO("EtwEventWriteFull Status: 0x%08X", Status);

	if (!NT_SUCCESS(Status = NtTraceEvent(NULL, 0, 0, NULL)))
	{
		NT_ERROR("NtTraceEvent");
		return 1;
	}

	INFO("NtTraceEvent Status: 0x%08X", Status);

	RemoveHardwareBreakpoint();

	OKAY("Done!");

	CHAR("Quit...");
	getchar();

	return 0;

}