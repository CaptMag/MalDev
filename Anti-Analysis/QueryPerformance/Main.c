#include "box.h"

int main()
{

	if (!QueryInformation())
	{
		PRINT_ERROR("QueryInformation");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}