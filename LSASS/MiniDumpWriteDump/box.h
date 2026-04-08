#pragma once
#include <Windows.h>
#include <stdio.h>
#include <minidumpapiset.h>

#pragma comment(lib, "dbghelp.lib")

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())


/**
* @brief
*	Used to Get the Process ID (PID) and a Handle to a target process
* 
* @param ProcName
*	Specified Target Process Name
* 
* @param PID
*	pointer to a DWORD used to store the target process's PID
* 
* @param hProcess
*	pointer to a HANDLE used to store the target process's Handle
* 
* @return BOOL
*	True on Success, False on Failure
*/
BOOL GetRemoteProcID
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
);

/**
* @brief
*	Used to Create a Dump File via MiniDumpWriteDump
* 
* @param FileName
*	Specified Name for .dmp file
* 
* @param hProcess
*	Handle to target process
* 
* @param PID
*	Target process's Process Identification (PID)
* 
* @return BOOL
*	True on Success, False on Failure
*/
BOOL DumpViaMiniDump
(
	IN LPCSTR FileName,
	IN HANDLE hProcess,
	IN DWORD PID
);

/**
* @brief
*	Callback Routine for DumpViaMiniDump
* 
* @param pParam
*	Application-defined parameter
* 
* @param pInput
*	Pointer to struct PMINIDUMP_CALLBACK_INPUT
* 
* @param pOutput
*	Pointer to struct PMINIDUMP_CALLBACK_OUTPUT
* 
* @return BOOL
*	True on Success, False on Failure
*/
BOOL CALLBACK MiniDumpCallBack
(
	PVOID pParam,
	PMINIDUMP_CALLBACK_INPUT pInput,
	PMINIDUMP_CALLBACK_OUTPUT pOutput
);