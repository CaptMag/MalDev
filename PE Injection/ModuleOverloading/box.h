#pragma once
#include <Windows.h>
#include <stdio.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", status)

#define LOADAPI(hModule, Type, Name) \
    Type Name = (Type)GetProcAddress(hModule, #Name)

#define CLOSEHANDLE(Handle)                         \
    if (Handle){                                    \
        CloseHandle(Handle);                        \
        printf("[v] [0x%p] %s Closed!\n", Handle, #Handle); \
    }

#define FREEMEMORY(Buffer)                                  \
    if (Buffer) {                                           \
        VirtualFree(Buffer, 0, MEM_RELEASE);                \
        printf("[v] Released %p bytes\n", Buffer); \
    }

typedef void (WINAPI* PMAIN)(void);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
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

typedef NTSTATUS (NTAPI* pNtCreateSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

typedef NTSTATUS (NTAPI* pNtMapViewOfSection)(
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

/**
* @brief
*   Read a Target PE file, get its file size and save it into lpBuffer & nNumberOfBytesToRead
* 
* @param PeName:
*   Target Portable Executable File
* 
* @param lpBuffer:
*   OUT Param, used to store the File's size
* 
* @param nNumberOfBytesToRead
*   Used for Heap Allocation
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL ReadTargetFile
(
    IN LPCSTR PeName,
    OUT LPVOID* lpBuffer,
    OUT DWORD* nNumberOfBytesToRead
);

/**
* @brief
*   Creates a New Section via NtCreateSection and Maps it via NtMapViewOfSection
* 
* @param DllFile:
*   Target DLL File
* 
* @param DllBaseAddress:
*   OUT Param, used to store the targeted Dll's Base Address
* 
* @param ImageSize:
*   OUT Param, Used to Store the targeted Dll's Image Size via SizeOfImage
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL MapDllFile
(
    IN LPCSTR DllFile,
    OUT PVOID* DllBaseAddress,
    OUT SIZE_T* ImageSize
);

/**
* @brief
*   Used To Manually Fix the Relocation Table To Help with PE addressing
* 
* @param RelocRVA:
*   Relative Virtual Address for targeted PE
* 
* @param PeBase:
*   Base Address For Targeted PE
* 
* @param dwDelta:
*   PE's perferred address
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL fixReloc
(
    IN DWORD RelocRVA,
    IN PVOID PeBase,
    IN DWORD_PTR dwDelta
);

/**
* @brief
*   Manually fix the Import Address Table used for Importing Functions (via their respective DLLs)
* 
* @param pImgDataDir:
*   IN Param for the Data Directory which can be accessed via  pImgNt->OptionalHeader.DataDirectory
* 
* @param dllBase:
*   PE Base Address (works for both DLLs and EXEs)
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL FixIAT
(
    IN PIMAGE_DATA_DIRECTORY pImgDataDir,
    IN PBYTE dllBase
);

/**
* @brief
*   Used To change the Memory Protection of a targeted PE
* 
* @param TargetBaseAddress:
*   The Base Address of a targeted PE file
* 
* @param lpFile
*   Target PE File used for PE parsing
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL ChangeProtection
(
    IN PVOID TargetBaseAddress,
    IN LPVOID lpFile
);


/**
* @brief
*   Overwrite the Memory of a Targeted PE File
* 
* @param MappedAddress:
*   The Address of the targeted PE
* 
* @param ImageSize:
*   ImageSize of the targeted PE
* 
* @param Buffer:
*   Payload (can be another PE)
* 
* @param BufferSize:
*   Size of Payload
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL OverwriteTargetDll
(
    IN PVOID MappedAddress,
    IN SIZE_T ImageSize,
    IN PBYTE Buffer,
    IN SIZE_T BufferSize
);

/**
* @brief
*   ModuleOverload, Used to store another PE into a targeted, legitimate DLL
* 
* @param PePayload
*   Specified PE file used as the payload
* 
* @param TargetDll
*   Generally a legitimate Windows DLL used as a target to store the PePayload
* 
* @return BOOL
*   True on Success, FALSE on Failure
*/
BOOL ModuleOverload
(
    IN LPCSTR PePayload,
    IN LPCSTR TargetDll
);