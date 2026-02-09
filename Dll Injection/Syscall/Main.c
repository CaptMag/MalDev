#include "box.h"

#define TARGET		L"Notepad.exe"
#define DllPath		// insert Dll Path

int main()
{

	DWORD PID = NULL;
	HANDLE hProcess = NULL;

	if (!GetRemoteProcessHandle(TARGET, &PID, &hProcess))
	{
		PRINT_ERROR("GetRemoteProcID");
		return 1;
	}

	if (!DllInject(DllPath, hProcess, PID))
	{
		PRINT_ERROR("DllInject");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}