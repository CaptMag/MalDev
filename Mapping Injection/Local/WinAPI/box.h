#pragma once
#include <Windows.h>
#include <stdio.h>

#pragma comment (lib, "OneCore.lib")

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

BOOL LocalMappingInjection
(
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sSizeofShellcode,
	OUT PVOID* pAddress
);