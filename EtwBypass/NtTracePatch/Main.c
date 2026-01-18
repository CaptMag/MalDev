#include "Box.h"

int main()
{

	if (!PatchNtTrace())
	{
		PRINT_ERROR("PatchNtTrace");
		return 1;
	}

	printf("Press Enter to Quit...\n");
	getchar();

	return 0;
}