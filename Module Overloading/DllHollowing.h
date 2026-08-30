#pragma once
#include <Windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* fnDllMain)					    (HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI* MAIN)							();

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0x00)

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

#define U_PTR( x )			( ULONG_PTR )( x )
#define C_PTR( x )			( PVOID )( x )

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1, // The mapped view of the section will be mapped into any child processes created by the process.
    ViewUnmap = 2  // The mapped view of the section will not be mapped into any child processes created by the process.
} SECTION_INHERIT;

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );


typedef struct
{

    struct
    {

        HMODULE Ntdll;

    }Module;

    struct
    {

        pNtCreateSection NtCreateSection;
        pNtMapViewOfSection NtMapViewOfSection;

    } Ntapi;

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

BOOL ReadTargetFileW
(
    _In_ LPCWSTR PeName,
    _Out_ LPVOID* lpBuffer
);

BOOL DllHollowExecution
(
    _In_ LPCWSTR TargetDll,
    _In_ LPVOID TargetPayloadBuffer
);