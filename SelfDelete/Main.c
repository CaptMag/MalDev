#include "SelfDelete.h"

int main()
{

	if (!DeleteCurrentFile())
	{
		PRINT_ERROR("DeleteRunningFile");
		return 1;
	}

	OKAY("DONE!");

	CHAR("Quit...");
	getchar();

	return 0;

}