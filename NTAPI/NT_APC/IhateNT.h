#pragma once

#ifndef IHATENT_H
#define IHATENT_H

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#endif

/* If winternl.h isn't available, define CLIENT_ID and OBJECT_ATTRIBUTES minimal types */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

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


typedef NTSTATUS(NTAPI* PFN_NtOpenProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
    );

typedef NTSTATUS(NTAPI* PFN_NtOpenThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* PFN_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* PFN_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,      
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

typedef NTSTATUS(NTAPI* PFN_NtWaitForSingleObject)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE Handle);

typedef VOID(NTAPI* PPS_APC_ROUTINE)(ULONG_PTR Parameter);

#endif // IHATENT_H