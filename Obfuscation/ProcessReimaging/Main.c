#include "box.h"

#define BADEXE "C:\\Windows\\System32\\notepad.exe"
#define VICTIMEXE "C:\\Windows\\System32\\cmd.exe"

int main()
{

	if (!ProcessReimaging(BADEXE, VICTIMEXE))
	{
		PRINT_ERROR("ProcessReimaging");
		return 1;
	}

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}