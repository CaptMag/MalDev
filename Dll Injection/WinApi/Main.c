#include "box.h"

#define dllPath  "C:Users\\..." // add your dll path or edit main to use argv/argc

int main()
{

	DWORD PID = NULL;
	HANDLE hProcess = NULL;

	if (!GetRemoteProcID(L"RuntimeBroker.exe", &PID, &hProcess))
	{
		PRINT_ERROR("GetRemoteProcID");
		return 1;
	}

	if (!InjectDll(dllPath, hProcess, PID))
	{
		PRINT_ERROR("InjectDll");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	CloseHandle(hProcess);

	return 0;

}