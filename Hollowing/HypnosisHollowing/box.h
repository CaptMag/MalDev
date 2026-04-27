#pragma once
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef LONG NTSTATUS;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

//typedef struct _PROCESS_BASIC_INFORMATION {
//	PVOID Reserved1;
//	PVOID PebBaseAddress;
//	PVOID Reserved2[2];
//	ULONG_PTR UniqueProcessId;
//	PVOID Reserved3;
//} PROCESS_BASIC_INFORMATION;

/**
* @brief
*	Create a new user-defined process using CreateProcessA
*	This creates the process in a debug state via DEBUG_ONLY_THIS_PROCESS
*
* @param ProcessName
*	User-defined process name/process path
* 
* @param TID
*	Used to store process's Thread ID
*
* @param PID
*	Used to store process's Process ID
*
* @param hProcess
*	Used to store the process's Process Handle
*
* @param hThread
*	Used to the process's Thread Handle
*/
BOOL CreateDebugedProcess
(
	IN LPCSTR ProcessName,
	OUT DWORD* TID,
	OUT DWORD* PID,
	OUT HANDLE* hProcess,
	OUT HANDLE* hThread
);

/**
* @brief
*	Reads the targeted PE file, and allocates the proper amount of heap onto the buffer respectively.
* 
* @param PeName
*	File Name, Example: "Notepad.exe"
* 
* @param lpBuffer
*	OUT param for properly allocated buffer respective to its file
* 
* @param nNumberOfBytesToRead
*	OUT param for storing file size
*/
BOOL ReadTargetFile
(
	IN LPCSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
);

/**
* @brief
*	Function to perfrom Process Hollowing. Involves taking a target process,
*	"hollowing" out the memory (or in this case overwriting it) before replacing it
*	with out payload (calc.exe)
* 
* @param PID:
*	Target Process's Process ID
* 
* @param hThread:
*	Thread handle to target process
* 
* @param hProcess:
*	Process handle to target process
* 
* @param rBuffer:
*	Remote Payload
* 
* @param lppBuffer:
*	Local Payload
* 
* @param Delta:
*	PE ImageBase perferred address
*/
BOOL ProcessHollowing
(
	IN DWORD PID,
	IN HANDLE hThread,
	IN HANDLE hProcess,
	IN LPVOID* rBuffer,
	IN LPVOID lppBuffer,
	OUT DWORD* Delta
);

/**
* @brief
*	Utilize Process Hypnosis for Payload execution
* 
* @param lppBuffer:
*	payload
* 
* @param rBuffer:
*	Target PE base address
* 
* @param PID:
*	Process ID
* 
* @param hProcess:
*	Process Handle for target process
*/
BOOL ProcessHypnosis
(
	IN LPVOID lppBuffer,
	IN PVOID* rBuffer,
	IN DWORD PID,
	IN HANDLE hProcess
);