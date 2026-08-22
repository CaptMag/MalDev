#pragma once
#include <Windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

BOOL CreateSuspendedProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ HANDLE* ThreadHandle
);

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ LPVOID* lpBuffer
);

BOOL PerformHollowExecution
(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ LPVOID TargetPayloadBuffer
);