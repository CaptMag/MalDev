#include "LocalPeExecution.h"

int main()
{

	LPVOID TargetPayloadBuffer = NULL;

	if (!ReadTargetFileW(L"C:\\Windows\\System32\\calc.exe", &TargetPayloadBuffer))
	{
		PRINT_ERROR("ReadTargetFileW");
		return 1;
	}

	if (!PortableExecutableInjection(TargetPayloadBuffer))
	{
		PRINT_ERROR("PortableExecutableInjection");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}