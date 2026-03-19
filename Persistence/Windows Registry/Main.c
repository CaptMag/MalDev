#include "box.h"

/**
* You can change the same of the newly created services
* I just made it "persistence" so I can identify it easily :)
*/

int main()
{

	if (!WindowsRegistry())
	{
		PRINT_ERROR("WindowsRegistry");
		return 1;
	}


	OKAY("DONE!");

	return 0;

}