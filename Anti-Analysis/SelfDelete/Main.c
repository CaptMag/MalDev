#include "box.h"

int main()
{

	if (!SelfDelete())
	{
		PRINT_ERROR("SelfDelete");
		return 1;
	}

	return 0;

}