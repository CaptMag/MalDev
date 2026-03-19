#include "box.h"

// https://learn.microsoft.com/en-us/windows/win32/services/installing-a-service

BOOL WindowsServices()
{

	SC_HANDLE schSCManager = NULL,
			  schService   = NULL; // just used for status

	WCHAR ExePath[MAX_PATH];
	GetModuleFileNameW(NULL, ExePath, MAX_PATH); // gets executable path

	schSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!schSCManager)
	{
		WARN("Failed To Establish Connection To Windows Services!");
		PRINT_ERROR("OpenSCManagerW");
		return FALSE;
	}

	schService = CreateServiceW(schSCManager, L"persistence", L"persistence", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, ExePath, NULL, NULL, NULL, NULL, NULL);
	if (!schService)
	{
		WARN("Failed To Create a New Service!");
		PRINT_ERROR("CreateServiceW");
		return FALSE;
	}

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService);

	return TRUE;

}