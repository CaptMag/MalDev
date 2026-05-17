#pragma once
#include <Windows.h>
#include <winternl.h>

#define          LoadLibraryA_HASH                  0x5FBFF0FB
#define          VirtualAlloc_HASH                  0x382C0F97
#define          VirtualProtect_HASH                0x844FF18D
#define          RtlAddFunctionTable_HASH           0xBDB9F1AE
#define          NtFlushInstructionCache_HASH       0x80183ADF
#define          kernel32dll_HASH                   0x7040EE75
#define          ntdlldll_HASH                      0x22D3B5ED

#define LOADAPIHASH(Type, Name, hModule, Hash) \
    Type Name = (Type)GetHashAddress(GetModuleHandleH(hModule), Hash)

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef LPVOID(WINAPI* PFN_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef BOOLEAN(WINAPI* PFN_RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

typedef NTSTATUS(NTAPI* PFN_NTFLUSHINSTRUCTIONCACHE)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);

typedef BOOL(WINAPI* PFN_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);

typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef BOOL(WINAPI* PDLLMAIN)(HINSTANCE, DWORD, LPVOID);