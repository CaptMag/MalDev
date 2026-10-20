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

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ LPVOID* lpBuffer,
	_Out_ DWORD* nNumberOfBytesToRead
);

BOOL GetRemoteId
(
	_In_ LPCWSTR ProcName,
	_Out_ DWORD* PID,
	_Out_ HANDLE* hProcess
);

DWORD RvaOffset
(
	_In_ DWORD dwRva,
	_In_ UINT_PTR PeBaseAddress
);

DWORD GetReflectiveLdrOffset
(
	_In_ UINT_PTR ReflectiveLdrBuffer
);

BOOL InjectReflectiveDll
(
	_In_ HANDLE hProcess,
	_In_ DWORD ReflectiveFunctionOffset,
	_In_ PBYTE ReflectiveDllBuffer,
	_In_ DWORD ReflectiveDllSize
);