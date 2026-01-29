#pragma once
#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

typedef struct _Syscall_Info {
    PVOID Nt_Function;
    DWORD SSN;
    PVOID SyscallInstruction;
} SYSCALL_INFO, * PSYSCALL_INFO;

PVOID WalkPeb();

BOOL GetEAT
(
    IN PVOID Ntdllbase,
    OUT PIMAGE_EXPORT_DIRECTORY* pImgDir
);

DWORD GetBaseHash
(
    IN char* FuncName,
    IN PVOID Ntdllbase,
    IN PIMAGE_EXPORT_DIRECTORY pImgExport
);

BOOL MagmaGate
(
    IN PIMAGE_EXPORT_DIRECTORY pImgDir,
    IN PVOID Ntdllbase,
    IN DWORD ApiHash,
    OUT PSYSCALL_INFO pSysInfo
);