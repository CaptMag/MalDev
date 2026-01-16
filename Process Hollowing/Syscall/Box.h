#pragma once
#include <windows.h>
#include <stdio.h>

#define FILE_OPEN                           0x00000001
#define FILE_NON_DIRECTORY_FILE             0x00000040
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define FILE_SYNCHRONOUS_IO_NONALERT        0x00000020


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", status)

typedef unsigned __int64 QWORD;

DWORD fn_NtAllocateVirtualMemorySSN;
DWORD fn_NtWriteVirtualMemorySSN;
DWORD fn_NtProtectVirtualMemorySSN;
DWORD fn_NtWaitForSingleObjectSSN;
DWORD fn_NtGetContextThreadSSN;
DWORD fn_NtSetContextThreadSSN;
DWORD fn_NtResumeThreadSSN;
DWORD fn_NtCreateFileSSN;
DWORD fn_NtReadFileSSN;
DWORD fn_NtQueryInformationFileSSN;


QWORD fn_NtAllocateVirtualMemorySyscall;
QWORD fn_NtWriteVirtualMemorySyscall;
QWORD fn_NtProtectVirtualMemorySyscall;
QWORD fn_NtWaitForSingleObjectSyscall;
QWORD fn_NtGetContextThreadSyscall;
QWORD fn_NtSetContextThreadSyscall;
QWORD fn_NtResumeThreadSyscall;
QWORD fn_NtCreateFileSyscall;
QWORD fn_NtReadFileSyscall;
QWORD fn_NtQueryInformationFileSyscall;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,                   // q: FILE_DIRECTORY_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileFullDirectoryInformation,                   // q: FILE_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBothDirectoryInformation,                   // q: FILE_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBasicInformation,                           // qs: FILE_BASIC_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileStandardInformation,                        // q: FILE_STANDARD_INFORMATION, FILE_STANDARD_INFORMATION_EX
    FileInternalInformation,                        // q: FILE_INTERNAL_INFORMATION
    FileEaInformation,                              // q: FILE_EA_INFORMATION (requires FILE_READ_EA)
    FileAccessInformation,                          // q: FILE_ACCESS_INFORMATION
    FileNameInformation,                            // q: FILE_NAME_INFORMATION
    FileRenameInformation,                          // s: FILE_RENAME_INFORMATION (requires DELETE) // 10
    FileLinkInformation,                            // s: FILE_LINK_INFORMATION
    FileNamesInformation,                           // q: FILE_NAMES_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileDispositionInformation,                     // s: FILE_DISPOSITION_INFORMATION (requires DELETE)
    FilePositionInformation,                        // qs: FILE_POSITION_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileFullEaInformation,                          // q: FILE_FULL_EA_INFORMATION (requires FILE_READ_EA)
    FileModeInformation,                            // qs: FILE_MODE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileAlignmentInformation,                       // q: FILE_ALIGNMENT_INFORMATION
    FileAllInformation,                             // q: FILE_ALL_INFORMATION
    FileAllocationInformation,                      // s: FILE_ALLOCATION_INFORMATION (requires FILE_WRITE_DATA)
    FileEndOfFileInformation,                       // s: FILE_END_OF_FILE_INFORMATION (requires FILE_WRITE_DATA) // 20
    FileAlternateNameInformation,                   // q: FILE_NAME_INFORMATION
    FileStreamInformation,                          // q: FILE_STREAM_INFORMATION
    FilePipeInformation,                            // qs: FILE_PIPE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FilePipeLocalInformation,                       // q: FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation,                      // qs: FILE_PIPE_REMOTE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileMailslotQueryInformation,                   // q: FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation,                     // s: FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation,                     // q: FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation,                        // q: FILE_OBJECTID_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileCompletionInformation,                      // s: FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation,                     // s: FILE_MOVE_CLUSTER_INFORMATION (requires FILE_WRITE_DATA)
    FileQuotaInformation,                           // q: FILE_QUOTA_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileReparsePointInformation,                    // q: FILE_REPARSE_POINT_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileNetworkOpenInformation,                     // q: FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation,                    // q: FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation,                        // s: FILE_TRACKING_INFORMATION (requires FILE_WRITE_DATA)
    FileIdBothDirectoryInformation,                 // q: FILE_ID_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileIdFullDirectoryInformation,                 // q: FILE_ID_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileValidDataLengthInformation,                 // s: FILE_VALID_DATA_LENGTH_INFORMATION (requires FILE_WRITE_DATA and/or SeManageVolumePrivilege)
    FileShortNameInformation,                       // s: FILE_NAME_INFORMATION (requires DELETE) // 40
    FileIoCompletionNotificationInformation,        // qs: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since VISTA
    FileIoStatusBlockRangeInformation,              // s: FILE_IOSTATUSBLOCK_RANGE_INFORMATION (requires SeLockMemoryPrivilege)
    FileIoPriorityHintInformation,                  // qs: FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX (q: requires FILE_READ_DATA)
    FileSfioReserveInformation,                     // qs: FILE_SFIO_RESERVE_INFORMATION (q: requires FILE_READ_DATA)
    FileSfioVolumeInformation,                      // q: FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation,                        // q: FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation,             // q: FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation,                  // q: FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation,             // q: FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation,             // q: FILE_ID_GLOBAL_TX_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since WIN7 // 50
    FileIsRemoteDeviceInformation,                  // q: FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,                          // q:
    FileNumaNodeInformation,                        // q: FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation,                    // q: FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation,                  // q: FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck,         // s: FILE_RENAME_INFORMATION // (kernel-mode only) // since WIN8
    FileLinkInformationBypassAccessCheck,           // s: FILE_LINK_INFORMATION // (kernel-mode only)
    FileVolumeNameInformation,                      // q: FILE_VOLUME_NAME_INFORMATION
    FileIdInformation,                              // q: FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation,                 // q: FILE_ID_EXTD_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // 60
    FileReplaceCompletionInformation,               // s: FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation,                  // q: FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation,             // q: FILE_ID_EXTD_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since THRESHOLD
    FileDispositionInformationEx,                   // s: FILE_DISPOSITION_INFO_EX (requires DELETE) // since REDSTONE
    FileRenameInformationEx,                        // s: FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck,       // s: FILE_RENAME_INFORMATION_EX // (kernel-mode only)
    FileDesiredStorageClassInformation,             // qs: FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation,                            // q: FILE_STAT_INFORMATION
    FileMemoryPartitionInformation,                 // s: FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation,                          // q: FILE_STAT_LX_INFORMATION (requires FILE_READ_ATTRIBUTES and FILE_READ_EA) // since REDSTONE4 // 70
    FileCaseSensitiveInformation,                   // qs: FILE_CASE_SENSITIVE_INFORMATION
    FileLinkInformationEx,                          // s: FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck,         // s: FILE_LINK_INFORMATION_EX // (kernel-mode only)
    FileStorageReserveIdInformation,                // qs: FILE_STORAGE_RESERVE_ID_INFORMATION
    FileCaseSensitiveInformationForceAccessCheck,   // qs: FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation,                     // qs: FILE_KNOWN_FOLDER_INFORMATION // since WIN11
    FileStatBasicInformation,                       // qs: FILE_STAT_BASIC_INFORMATION // since 23H2
    FileId64ExtdDirectoryInformation,               // q: FILE_ID_64_EXTD_DIR_INFORMATION
    FileId64ExtdBothDirectoryInformation,           // q: FILE_ID_64_EXTD_BOTH_DIR_INFORMATION
    FileIdAllExtdDirectoryInformation,              // q: FILE_ID_ALL_EXTD_DIR_INFORMATION
    FileIdAllExtdBothDirectoryInformation,          // q: FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION
    FileStreamReservationInformation,               // q: FILE_STREAM_RESERVATION_INFORMATION // since 24H2
    FileMupProviderInfo,                            // qs: MUP_PROVIDER_INFORMATION
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef _Function_class_(IO_APC_ROUTINE)
VOID NTAPI IO_APC_ROUTINE(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
);

typedef IO_APC_ROUTINE* PIO_APC_ROUTINE;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _FILE_STANDARD_INFORMATION
{
    LARGE_INTEGER AllocationSize;       // The file allocation size in bytes. Usually, this value is a multiple of the sector or cluster size of the underlying physical device.
    LARGE_INTEGER EndOfFile;            // The end of file location as a byte offset.
    ULONG NumberOfLinks;                // The number of hard links to the file.
    BOOLEAN DeletePending;              // The delete pending status. TRUE indicates that a file deletion has been requested.
    BOOLEAN Directory;                  // The file directory status. TRUE indicates the file object represents a directory.
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef VOID(NTAPI* RtlInitUnicodeString)(
    PUNICODE_STRING,
    PCWSTR
    );

#define InitializeObjectAttributes(p, n, a, r, s) \
{                                                 \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);      \
    (p)->RootDirectory = r;                        \
    (p)->Attributes = a;                           \
    (p)->ObjectName = n;                           \
    (p)->SecurityDescriptor = s;                   \
    (p)->SecurityQualityOfService = NULL;          \
}

NTSTATUS NtQueryInformationFile(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS NtReadFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

NTSTATUS NtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

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
(
    IN LPCSTR ProcessName,
    OUT PHANDLE hProcess,
    OUT PHANDLE hThread
);

BOOL ReadTargetFile
(
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
    IN PIMAGE_SECTION_HEADER pImgSecHeader,
    IN PIMAGE_DATA_DIRECTORY pImgDataDir,
    IN LPVOID lppBuffer
);

BOOL GetThreadCtx
(
    IN HANDLE hProcess,
    IN HANDLE hThread,
    IN PIMAGE_NT_HEADERS pImgNt,
    IN LPVOID rBuffer
);