#include "PersistViaWindowsServices.h"

int main()
{

	if (!PersistViaWindowsServices())
	{
		PRINT_ERROR("WindowsServices");
		return 1;
	}

	return 0;

}