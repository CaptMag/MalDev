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



typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE Handle);

typedef VOID(NTAPI* PPS_APC_ROUTINE)(ULONG_PTR Parameter);

BOOL CreateSuspendedProcess
(
    IN LPCSTR ProcessName,
    OUT PHANDLE hProcess,
    OUT PHANDLE hThread,
    OUT PDWORD PID
);

BOOL ApcInject
(
    IN HANDLE hProcess,
    IN HANDLE hThread,
    IN BYTE* pShellcode,
    IN SIZE_T sShellSize
);