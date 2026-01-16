#include "Box.h"

int main()
{

	if (!PatchEtw())
	{
		PRINT_ERROR("PatchEtw");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}