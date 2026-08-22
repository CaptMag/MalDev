#include "NtPeInjection.h"

int main()
{

	LPVOID TargetPayloadBuffer = NULL;

	if (!ReadTargetFileW(L"C:\\Windows\\System32\\calc.exe", &TargetPayloadBuffer))
	{
		PRINT_ERROR("ReadTargetFileW");
		return 1;
	}

	INFO("Peforming Local Pe Injection...");
	if (!NtPeInjection(TargetPayloadBuffer))
	{
		PRINT_ERROR("NtPeInjection");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}