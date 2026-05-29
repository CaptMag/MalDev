#pragma once
#include <Windows.h>
#include <stdio.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define STATUS_BUFFER_TOO_SMALL (NTSTATUS)0xC0000023
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", status)

#define LOADAPI(Type, Name, hModule) \
    Type Name = (Type)GetProcAddress(GetModuleHandleA(hModule), #Name)

typedef NTSTATUS (NTAPI* fnNtQueryInformationToken)(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* fnNtOpenThreadToken)(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _Out_ PHANDLE TokenHandle
);

typedef NTSTATUS (NTAPI* fnNtOpenProcessToken)(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
);

BOOL GetCurrentUserToken
(
    OUT HANDLE* hToken
);

BOOL EnumerateUserTokenA
(
    IN HANDLE Token
);

BOOL StealPrimaryTokenA
(
    IN HANDLE hToken,
    IN DWORD PID,
    OUT HANDLE* NewPrimaryToken
);

BOOL ImpersonateTokenA
(
    IN HANDLE ProcessToken
);

BOOL SpawnProcessWithDuplicateTokenA
(
    IN HANDLE hToken,
    IN HANDLE DuplicateHandle
);