#pragma once


#include <Windows.h>
#include <stdio.h>
#include <psapi.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;



typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;


typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;


typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

BOOL local_map_inject
(
    IN HANDLE hProcess,
    IN HANDLE hThread,
    IN PBYTE sShellcode,
    IN SIZE_T sShellSize,
    OUT PVOID* pAddress
);