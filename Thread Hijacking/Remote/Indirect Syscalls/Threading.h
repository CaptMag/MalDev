#pragma once
#include <Windows.h>
#include <stdio.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] "      MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)


typedef unsigned __int64 QWORD;


DWORD fn_NtAllocateVirtualMemorySSN;
DWORD fn_NtWriteVirtualMemorySSN;
DWORD fn_NtProtectVirtualMemorySSN;
DWORD fn_NtWaitForSingleObjectSSN;
DWORD fn_NtGetContextThreadSSN;
DWORD fn_NtSetContextThreadSSN;
DWORD fn_NtResumeThreadSSN;


QWORD fn_NtAllocateVirtualMemorySyscall;
QWORD fn_NtWriteVirtualMemorySyscall;
QWORD fn_NtProtectVirtualMemorySyscall;
QWORD fn_NtWaitForSingleObjectSyscall;
QWORD fn_NtGetContextThreadSyscall;
QWORD fn_NtSetContextThreadSyscall;
QWORD fn_NtResumeThreadSyscall;


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

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);


extern NTSTATUS NtSetContextThread(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
    );

extern NTSTATUS NtGetContextThread(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
    );

extern NTSTATUS NtResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );


BOOL CreateSuspendedProcess
(IN LPCSTR lpProcessName,
    OUT DWORD* dwProcessId,
    IN HANDLE hParent,
    OUT HANDLE* hProcess,
    OUT HANDLE* hThread);

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