#pragma once
#include <Windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

BOOL CreateSpoofedProcess
(
	_In_ LPCWSTR ProcessPath,
	_In_ HANDLE ParentHandle,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle,
	_Out_ DWORD* ProcessId,
	_Out_ DWORD* ThreadId
);