#pragma once
#include <Windows.h>
#include <stdio.h>

typedef HMODULE(WINAPI* fnLoadLibraryA)					(LPCSTR lpLibFileName);
typedef LPVOID(WINAPI*	fnVirtualAlloc)					(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI*	fnVirtualProtect)			    (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef NTSTATUS(NTAPI* fnNtFlushInstructionCache)		(HANDLE hProcess, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef BOOL(WINAPI*	fnDllMain)					    (HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI*	MAIN)							();


#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

#define U_PTR( x )			( ULONG_PTR )( x )
#define C_PTR( x )			( PVOID )( x )

typedef struct
{

	struct
	{

		PIMAGE_NT_HEADERS		pImgNtHdrs;
		PIMAGE_SECTION_HEADER	pImgSecHdr;

		PIMAGE_DATA_DIRECTORY	pEntryImportDataDir;
		PIMAGE_DATA_DIRECTORY	pEntryBaseRelocDataDir;
		PIMAGE_DATA_DIRECTORY	pEntryExceptionDataDir;
		PIMAGE_DATA_DIRECTORY	pEntryExportDataDir;
		PIMAGE_DATA_DIRECTORY	pEntryTLSDataDir;


	} PeHeaders;

} Win32, * pWin32;

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ LPVOID* lpBuffer
);

BOOLEAN PortableExecutableInjection
(
	_In_ LPVOID TargetPayloadBuffer
);