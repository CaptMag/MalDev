#include "ThreadlessInjection.h"

// References:
// https://github.com/CCob/ThreadlessInject
// https://github.com/lsecqt/ThreadlessInject-C-Implementation/tree/main

int main(void)
{

	LPCWSTR TargetDll		= L"kernel32.dll";
	LPCWSTR TargetProcess	= L"notepad++.exe";
	LPCSTR	TargetFunction	= "CreateEventW";

	if (!ThreadlessInjection(TargetDll, TargetFunction, TargetProcess))
	{
		PRINT_ERROR("ThreadlessInjection");
		return 1;
	}

	OKAY("Done!");
	
	CHAR("Quit...");
	getchar();

	return 0;

}