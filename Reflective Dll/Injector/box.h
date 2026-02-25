#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

BOOL ReadTargetFile
(
	IN LPCWSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
);

BOOL GetRemoteId
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
);

DWORD GetReflectiveLdrOffset
(
	IN UINT_PTR ReflectiveLdrBuffer
);

BOOL InjectReflectiveDll
(
	IN HANDLE hProcess,
	IN DWORD ReflectiveFunctionOffset,
	IN PBYTE ReflectiveDllBuffer,
	IN DWORD ReflectiveDllSize
);