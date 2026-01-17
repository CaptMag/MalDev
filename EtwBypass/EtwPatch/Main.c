#include "Box.h"

int main()
{

	if (!PatchEtw("EtwEventWrite"))
	{
		PRINT_ERROR("PatchEtw");
		return 1;
	}

	if (!PatchEtw("EtwEventWriteFull"))
	{
		PRINT_ERROR("PatchEtw");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}