#include "PPIDSpoof.h"

#define TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe"

int main(int argc, char* argv[])
{

	HANDLE ParentHandle = NULL, ProcessHandle = NULL, ThreadHandle = NULL;
	DWORD ProcessId = 0, ThreadId = 0;
	DWORD TargetProcessId = atoi(argv[1]);

	// you could also using a process enumeration function and not require any extra commands
	if (argc < 2)
	{
		WARN("TargetProcessId Not Supplied! Exiting!");
		return 1;
	}

	if (!(ParentHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetProcessId)) || ParentHandle == NULL)
	{
		PRINT_ERROR("OpenProcess");
		return 1;
	}

	INFO("Creating %ls w/ [%d] ProcessId", TARGET_PROCESS, TargetProcessId);
	if (!CreateSpoofedProcess(TARGET_PROCESS, ParentHandle, &ProcessHandle, &ThreadHandle, &ProcessId, &ThreadId))
	{
		PRINT_ERROR("CreateSpoofedProcess");
		return 1;
	}

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}