#include "PersistViaWindowsRegistry.h"

int main()
{

	if (!PersistViaWindowsRegistry())
	{
		PRINT_ERROR("PersistViaWindowsRegistry");
		return 1;
	}

	return 0;

}