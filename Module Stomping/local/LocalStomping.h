#pragma once
#include <Windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

BOOL StompLocalModule
(
	_In_ LPCWSTR TargetDll,
	_In_ LPCSTR TargetDllFunction,
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
);