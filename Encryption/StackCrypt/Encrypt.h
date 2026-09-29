#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <winternl.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

typedef struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} USTRING;

typedef NTSTATUS(WINAPI* _SystemFunction033) (
    struct ustring* data,
    struct ustring* key);

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;        // The exit status of the thread or STATUS_PENDING when the thread has not terminated. (GetExitCodeThread)
    PTEB TebBaseAddress;        // The base address of the memory region containing the TEB structure. (NtCurrentTeb)
    CLIENT_ID ClientId;         // The process and thread identifier of the thread.
    KAFFINITY AffinityMask;     // The affinity mask of the thread. (deprecated) (SetThreadAffinityMask)
    KPRIORITY Priority;         // The current priority of the thread. (GetThreadPriority)
    KPRIORITY BasePriority;     // The current base priority of the thread determined by the thread priority and process priority class.
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI* fnNtQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define LOADAPI(Type, Name, Module) \
Type Name = (Type)GetProcAddress(LoadLibraryW(Module), #Name);

BOOLEAN ThreadCrypt
(
    _In_ HANDLE ThreadHandle
);

BOOLEAN ThreadCryptSuspend(void);

BOOLEAN ThreadCryptResume(void);