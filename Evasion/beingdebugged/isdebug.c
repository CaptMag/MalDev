#include "debug.h"

BOOL NtIsDebug()
{

	HMODULE ntdll = NULL;
	ULONG_PTR ptrProcessDebugPort = NULL;
	ULONG ptrProcessDebugFlags = NULL;
	NTSTATUS status = NULL;

	ntdll = LoadLibraryA("ntdll.dll");

	NtQueryInformationProcess fn_NtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

	INFO("NtQueryInformationProcess Loaded [0x%p]", fn_NtQueryInformationProcess);

	status = fn_NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &ptrProcessDebugPort, sizeof(ptrProcessDebugPort), NULL);
	if (status == STATUS_SUCCESS)
	{
		if (ptrProcessDebugPort == 0)
		{
			INFO("ProcessDebugPort Value: [0x%p]", (PVOID)ptrProcessDebugPort); // returns 0x0
			OKAY("Not Being Debugged!");
		}
		else
		{
			INFO("ProcessDebugPort Value: [0x%p]", (PVOID)ptrProcessDebugPort); // returns 0xFF
			WARN("Being Debugged!");
		}
	}

	status = fn_NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &ptrProcessDebugFlags, sizeof(ptrProcessDebugFlags), NULL);
	if (status == STATUS_SUCCESS)
	{
		if (ptrProcessDebugFlags != 0) // Flipped
		{
			INFO("ProcessDebugFlags Value: [0x%p]", (PVOID)ptrProcessDebugFlags); // returns 0x1
			OKAY("Not Being Debugged!");
		}
		else
		{
			INFO("ProcessDebugFlags Value: [0x%p]", (PVOID)ptrProcessDebugFlags); // returns 0x0
			WARN("Being Debugged!");
		}
	}

}

BOOL CheckPeb()
{

	int debugFlag = checkflag();
	int beingDebugged = checkdebugger();

	PPEB pPeb = getPeb();
	OKAY("PEB: [0x%p]", pPeb);

	if (debugFlag != 0 || beingDebugged != 0)
	{
		INFO("Debugger detected! NtGlobalFlag=0x%x, BeingDebugged=%d", debugFlag, beingDebugged);
		WARN("Being Debugged!");
		return TRUE;
	}
	else
	{
		INFO("No debugger. NtGlobalFlag=0x%x, BeingDebugged=%d", debugFlag, beingDebugged);
		OKAY("Not Being Debugged");
		return FALSE;
	}

	return FALSE;

}