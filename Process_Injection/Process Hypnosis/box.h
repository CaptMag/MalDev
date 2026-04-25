#pragma once
#include <Windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())


/**
* @brief
*	Create a new user-defined process using CreateProcessA
*	This creates the process in a debug state via DEBUG_ONLY_THIS_PROCESS
* 
* @param ProcessName
*	User-defined process name/process path
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
*	Process-Hypnosis (originally written by CarlosG13) is a way of executing a buffer (i.e our Shellcode)
*	without calling heavily-monitored APIs such as VirtualAllocEx, VirtualProtect, CreateRemoteThreadEx, etc.
*	This is done via "freezing" the process (essentially another way to suspend process without calling CREATE_SUSPENDED).
* 
* @param PID
*	Process ID
* 
* @param hProcess
*	Target process's Handle
* 
* @param hThread
*	Target process's Thread Handle
* 
* @param Buffer
*	specified payload buffer
* 
* @param BufferSize
*	Size of payload
*/
BOOL ProcessHypnosis
(
	IN DWORD PID,
	IN DWORD TID,
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PBYTE Buffer,
	IN SIZE_T BufferSize
);