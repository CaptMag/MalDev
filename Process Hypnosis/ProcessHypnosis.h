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
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

BOOL CreateTargetProcess
(
	_In_ LPCWSTR TargetProcessPath,
	_Out_ HANDLE* ProcessHandle,
	_Out_ DWORD* ProcessId,
	_Out_ DWORD* ThreadId
);

BOOLEAN ExecuteProcessHypnosis
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize,
	_In_ HANDLE ProcessHandle,
	_In_ DWORD ProcessId,
	_In_ DWORD ThreadId
);
