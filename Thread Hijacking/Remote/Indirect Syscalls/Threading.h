#pragma once
#include <Windows.h>
#include <stdio.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] "      MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)

BOOL CreateSuspendedProcess
(
    IN LPCSTR ProcessName,
    OUT DWORD* PID,
    OUT HANDLE* hProcess,
    OUT HANDLE* hThread
);

BOOL IndirectSyscallInjection
(IN HANDLE hProcess,
    IN PBYTE pShellcode,
    IN SIZE_T sSizeOfShellcode,
    OUT PVOID* ppAddress);

BOOL HijackThread
(
    IN HANDLE hThread,
    IN PVOID ppAddress
);