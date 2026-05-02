#pragma once
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <intrin.h>

#define VIRTUALALLOCHASH 942411671
#define VIRTUALPROTECTHASH 2219831693
#define GETPROCADDRESSHASH 3476142879
#define LOADLIBRARYAHASH 1606414587
#define NTFLUSHINSTRUCTIONCACHEHASH 2149071583
#define KERNEL32HASH 1372930645
#define NTDLLHASH 584300013
#define MESSAGEBOXAHASH 944706740
#define USER32HASH 3642339283

#define LOADAPIHASH(Type, Name, hModule, Hash) \
    Type Name = (Type)GetHashAddress(GetModuleHandleH(hModule), Hash)

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef LPVOID(WINAPI* PFN_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef BOOLEAN(NTAPI* PFN_RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

typedef NTSTATUS(NTAPI* PFN_NTFLUSHINSTRUCTIONCACHE)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);

typedef BOOL(WINAPI* PFN_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);

typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef int (WINAPI* fnMessageBoxA)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
    );

typedef BOOL(WINAPI* PDLLMAIN)(HINSTANCE, DWORD, LPVOID);