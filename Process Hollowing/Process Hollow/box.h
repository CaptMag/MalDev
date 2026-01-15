#pragma once
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD PID
);

BOOL ReadTargetFile
(
	IN LPCSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
);

BOOL GrabPeHeader
(
	OUT PIMAGE_NT_HEADERS* pImgNt,
	OUT PIMAGE_SECTION_HEADER* pImgSecHeader,
	OUT PIMAGE_DATA_DIRECTORY* pImgDataDir,
	IN LPVOID lpFile
);

BOOL HollowExec
(
	IN HANDLE hProcess,
	IN PIMAGE_NT_HEADERS pImgNt,
	IN LPVOID* rBuffer,
	IN LPVOID PeBaseAddress,
	IN PIMAGE_SECTION_HEADER pImgSecHeader,
	IN PIMAGE_DATA_DIRECTORY pImgDataDir,
	IN LPVOID lppBuffer,
	OUT DWORD* Delta
);

BOOL GetThreadCtx
(
	IN HANDLE hProcess,
	IN HANDLE hThread,
	IN PIMAGE_NT_HEADERS pImgNt,
	IN LPVOID rBuffer
);