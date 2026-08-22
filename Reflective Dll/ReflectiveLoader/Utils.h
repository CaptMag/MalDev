#pragma once
#define WIN32_MEAN_AND_LEAN
#include <Windows.h>

#ifdef  __x86_64__
#define CurrentPeb __readgsqword( 0x60 )
#else
#define CurrentPeb __readgsqword( 0x30 )
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef HMODULE		(WINAPI* fnLoadLibraryA)				(LPCSTR lpLibFileName);
typedef LPVOID		(WINAPI* fnVirtualAlloc)				(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL		(WINAPI* fnVirtualProtect)			    (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef NTSTATUS	(NTAPI*  fnNtFlushInstructionCache)	    (HANDLE hProcess, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef BOOL		(WINAPI* fnDllMain)					    (HINSTANCE, DWORD, LPVOID);

#define          VirtualAlloc_HASH                  0x097BC257
#define          VirtualProtect_HASH                0xE857500D
#define          NtFlushInstructionCache_HASH       0x6269B87F
#define          GetProcAddress_HASH                0xDECFC1BF
#define          LoadLibraryA_HASH                  0xB7072FDB
#define          kernel32_dll_HASH                  0xADD31DF0
#define          ntdll_dll_HASH                     0x70E61753
#define          HASH_SEED							5381

#define U_PTR( x )			( ULONG_PTR )( x )
#define C_PTR( x )			( PVOID )( x )

typedef struct
{

	struct
	{

		HMODULE Kernel32;
        HMODULE Ntdll;

	} DllModule;

	struct
	{

		fnVirtualAlloc              pVirtualAlloc;
		fnVirtualProtect            pVirtualProtect;
		fnLoadLibraryA              pLoadLibraryA;
		fnNtFlushInstructionCache   pNtFlushInstructionCache;

	} Api;

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

} Win32, *pWin32;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;                             // +0x00
    USHORT MaximumLength;                      // +0x02
    PWSTR  Buffer;                             // +0x08
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                // +0x00
    UCHAR Initialized;                           // +0x04
    PVOID SsHandle;                              // +0x08
    LIST_ENTRY InLoadOrderModuleList;            // +0x10
    LIST_ENTRY InMemoryOrderModuleList;          // +0x20
    LIST_ENTRY InInitializationOrderModuleList;  // +0x30
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;               // +0x00
    LIST_ENTRY InMemoryOrderLinks;             // +0x10
    LIST_ENTRY InInitializationOrderLinks;     // +0x20
    PVOID DllBase;                             // +0x30
    PVOID EntryPoint;                          // +0x38
    ULONG SizeOfImage;                         // +0x40
    UNICODE_STRING FullDllName;                // +0x48
    UNICODE_STRING BaseDllName;                // +0x58
    ULONG Flags;                               // +0x68
    USHORT LoadCount;                          // +0x6C
    USHORT TlsIndex;                           // +0x6E
    LIST_ENTRY HashLinks;                      // +0x70
    ULONG TimeDateStamp;                       // +0x80
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

PVOID LoadDllModule
(
    _In_ DWORD DllModuleHash
);

PVOID ResolveHashedFunction
(
    _In_ pWin32 Win32,
    _In_ PVOID DllModuleBase,
    _In_ DWORD ApiHash
);

BOOL ResolveIAT
(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_DATA_DIRECTORY IatRva,
    _In_ pWin32 Win32
);

BOOL RelocSections
(
    _In_ DWORD RVA,
    _In_ PVOID ImageBase,
    _In_ DWORD_PTR Delta
);

BOOL ChangeMemoryProtection
(
    _In_ PVOID TargetBaseAddress,
    _In_ PIMAGE_NT_HEADERS pImgNt,
    _In_ pWin32 Win32
);

