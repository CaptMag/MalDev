#pragma once
#include <Windows.h>
#include <stdio.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] "      MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)

/*

    This will be slightly different from direct syscalls
    rather than just calling the function DIRECTLY, we will
    use a jmp instruction to retrive the syscall that we scrapped

    the code between direct and indirect syscalls will be almost identical
    however, in the ASM file we will no longer call syscall, and will
    instead issue a jmp instruction using the following QWORD values

*/


/*

    Don't be alarmed, since we are calling these functions via ASM
    there is no need to directly call them through WINAPI or NTAPI
    so just ignore the red lines, as they will be called indirectly
    skipping all the other Windows DLLs

*/


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

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


BOOL IndirectShellInjection(
    IN DWORD PID,
    IN HANDLE hProcess,
    IN PBYTE pShellcode,
    IN SIZE_T sSizeofShellcode
);