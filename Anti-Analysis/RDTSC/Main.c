#include "box.h"

int main()
{

	if (!ChkDebug())
	{
		PRINT_ERROR("ChkDebug");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}