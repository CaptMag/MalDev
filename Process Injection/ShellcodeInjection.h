#pragma once
#include <Windows.h>
#include <stdio.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", status)

/**
* @brief
*	Create a New Process Based on TargetProcessPath
* 
* @param TargetProcessPath:
*	Executable Name or Path
* 
* @param ProcessHandle:
*	Process Handle of Newly Created Process
* 
* @param ThreadHandle:
*	Thread Handle of Newly Created Process
* 
* @param ProcessId:
*	Process Identifier for Newly Created Process
* 
* @param ThreadId:
*	Thread Identifier for Newly Created Process
* 
* @return BOOL:
*	TRUE on Sucess, FALSE on Failure
*/
BOOL CreateTargetProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle,
	_Out_ DWORD* ProcessId,
	_Out_ DWORD* ThreadId
);

/**
* @brief
*	Inject Target Process w/ MSFVenom Calc Shellcode
* 
* @param ProcessHandle:
*	Target's Process Handle
* 
* @param ThreadHandle:
*	Target's Thread Handle
* 
* @param Payload:
*	User-Defined Payload (Shellcode)
* 
* @param PayloadSize:
*	Size Of Payload
* 
* @param ProcessId:
*	Target Process's uniquely identifiable Process ID
* 
* @param ThreadId:
*	Target Process's uniquely identifiable Thread ID
* 
* @return BOOL:
*	TRUE on Sucess, FALSE on Failure
*/
BOOL ShellcodeInjection
(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_In_ DWORD ProcessId,
	_In_ DWORD ThreadId
);