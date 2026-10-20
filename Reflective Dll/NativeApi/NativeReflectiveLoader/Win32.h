#pragma once
#include <Windows.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0x00)

#define          NtAllocateVirtualMemory_HASH    0xF783B8EC
#define          NtProtectVirtualMemory_HASH     0x50E92888
#define          NtFlushInstructionCache_HASH    0x6269B87F
#define          LdrGetProcedureAddress_HASH     0xFCE76BB6
#define          LdrLoadDll_HASH                 0x9E456A43
#define          RtlMultiByteToUnicodeN_HASH     0x6248898E
#define          ntdll_dll_HASH                  0x70E61753

typedef NTSTATUS(NTAPI* fnNtFlushInstructionCache)	(HANDLE hProcess, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef BOOL(WINAPI* fnDllMain)					    (HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI* MAIN)							();

#define U_PTR( x )			( ULONG_PTR )( x )
#define C_PTR( x )			( PVOID )( x )

typedef struct _BASE_RELOCATION_ENTRY {
    WORD	Offset : 12;
    WORD	Type : 4;
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

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

typedef NTSTATUS(NTAPI* fnLdrGetProcedureAddress)(
    _In_ PVOID BaseAddress,
    _In_opt_ PANSI_STRING Name,
    _In_opt_ ULONG Ordinal,
    _Out_ PVOID* ProcedureAddress
    );

typedef NTSTATUS(NTAPI* fnLdrLoadDll)(
    _In_opt_ PWSTR PathToFile,
    _In_opt_ PULONG Flags,
    _In_ PUNICODE_STRING ModuleFileName,
    _Out_ PVOID* ModuleHandle
    );

typedef NTSTATUS(NTAPI* fnRtlMultiByteToUnicodeN)(
    _Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    _In_ ULONG MaxBytesInUnicodeString,
    _Out_opt_ PULONG BytesInUnicodeString,
    _In_reads_bytes_(BytesInMultiByteString) PCSTR MultiByteString,
    _In_ ULONG BytesInMultiByteString
    );

typedef struct
{

    struct
    {

        HMODULE Ntdll;

    } Module;

    struct
    {

        fnNtAllocateVirtualMemory   NtAllocateVirtualMemory;        /*>>    Allocate a Block of Virtual Memory via NT Apis                          */
        fnNtProtectVirtualMemory    NtProtectVirtualMemory;         /*>>    Change Memory Protection Perms                                          */
        fnLdrLoadDll                LdrLoadDll;                     /*>>    Nt Variant for LoadLibrary (used to load in a Dll)                      */
        fnLdrGetProcedureAddress    LdrGetProcedureAddress;         /*>>    Nt Variant for GetProcAddress (Resolves Respective Function's Address)  */
        fnNtFlushInstructionCache   NtFlushInstructionCache;        /*>>    Flush CPU Instruction Cache                                             */
        fnRtlMultiByteToUnicodeN    RtlMultiByteToUnicodeN;         /*>>    Translates current string type (ANSI) to Unicode String (WIDE)          */

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

} Win32, * pWin32;

PVOID GetModuleByHash
(
    _In_ DWORD ModuleHash
);

PVOID ResolveHashedFunction
(
    _In_ pWin32 Win32,
    _In_ PVOID DllModuleBase,
    _In_ DWORD FunctionHash
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

