#pragma once
#include <Windows.h>
#include <stdio.h>
#include <UserEnv.h>
#pragma comment(lib, "Userenv.lib")

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0x00)

#define OBJ_CASE_INSENSITIVE                0x00000040L
#define FILE_SUPERSEDE                      0x00000000
#define FILE_SYNCHRONOUS_IO_NONALERT        0x00000020
#define RTL_MAX_DRIVE_LETTERS 32

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NTERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

#define L_PTR( x )          ( LPVOID )( x )
#define U_PTR( x )			( ULONG_PTR )( x )
#define C_PTR( x )			( PVOID )( x )

typedef struct _FILE_DISPOSITION_INFORMATION
{
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

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

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef _Function_class_(IO_APC_ROUTINE)
VOID NTAPI IO_APC_ROUTINE(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
);

typedef IO_APC_ROUTINE* PIO_APC_ROUTINE;

typedef _Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI USER_THREAD_START_ROUTINE(
    _In_ PVOID ThreadParameter
);

typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

_Struct_size_bytes_(TotalLength)
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;

} CURDIR, * PCURDIR;


typedef struct _RTLP_CURDIR_REF
{
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_MODULE {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,                        // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits,                             // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters,                              // q: IO_COUNTERS
    ProcessVmCounters,                              // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes,                                   // q: KERNEL_USER_TIMES // since VISTA
    ProcessBasePriority,                            // s: KPRIORITY
    ProcessRaisePriority,                           // s: PROCESS_RAISE_PRIORITY
    ProcessDebugPort,                               // q: HANDLE
    ProcessExceptionPort,                           // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken,                             // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation,                          // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize,                                 // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode,                    // qs: PROCESS_DEFAULT_HARD_ERROR_MODE
    ProcessIoPortHandlers,                          // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
    ProcessPooledUsageAndLimits,                    // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch,                         // qs: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,                            // s: PROCESS_USER_MODE_IOPL (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup,               // s: BOOLEAN
    ProcessPriorityClass,                           // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,                         // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount,                             // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask,                            // qs: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost,                           // qs: PROCESS_PRIORITY_BOOST
    ProcessDeviceMap,                               // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation,                      // qs: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation,                   // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information,                        // q: ULONG_PTR
    ProcessImageFileName,                           // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled,                   // q: PROCESS_LUID_DEVICE_MAPS_ENABLED
    ProcessBreakOnTermination,                      // qs: ULONG
    ProcessDebugObjectHandle,                       // q: HANDLE // 30
    ProcessDebugFlags,                              // qs: PROCESS_DEBUG_FLAGS
    ProcessHandleTracing,                           // qs: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority,                              // qs: IO_PRIORITY_HINT (s: requires SeIncreaseBasePriorityPrivilege)
    ProcessExecuteFlags,                            // qs: PROCESS_EXECUTE_FLAGS
    ProcessTlsInformation,                          // s: PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie,                                  // q: ULONG
    ProcessImageInformation,                        // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime,                               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority,                            // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback,                 // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation,                   // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx,                       // qs: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32,                      // q: UNICODE_STRING
    ProcessImageFileMapping,                        // q: HANDLE (input)
    ProcessAffinityUpdateMode,                      // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode,                    // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation,                        // q: PROCESS_GROUP_INFORMATION
    ProcessTokenVirtualizationEnabled,              // s: ULONG
    ProcessConsoleHostProcess,                      // qs: PROCESS_CONSOLE_HOST_PROCESS_INFORMATION
    ProcessWindowInformation,                       // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation,                       // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy,                        // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,         // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode,                      // qs: PROCESS_HANDLE_CHECKING_MODE; s: 0 disables, otherwise enables
    ProcessKeepAliveCount,                          // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles,                       // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl,                       // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable,                             // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode,                   // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation,                  // q: UNICODE_STRING // 60
    ProcessProtectionInformation,                   // q: PS_PROTECTION
    ProcessMemoryExhaustion,                        // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation,                        // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation,                  // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation,                // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved1Information
    ProcessAllowedCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved2Information
    ProcessSubsystemProcess,                        // s: void // EPROCESS->SubsystemProcess
    ProcessJobMemoryInformation,                    // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate,                               // qs: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose,    // qs: PROCESS_RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,                    // qs: PROCESS_IUM_CHALLENGE_RESPONSE
    ProcessChildProcessInformation,                 // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation,         // qs: BOOLEAN; s: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation,                    // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues,                            // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
    ProcessPowerThrottlingState,                    // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessActivityThrottlePolicy,                  // qs: Obsolete // PROCESS_ACTIVITY_THROTTLE_POLICY // ProcessReserved3Information
    ProcessWin32kSyscallFilterInformation,          // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets,             // s: BOOLEAN // 80
    ProcessWakeInformation,                         // q: PROCESS_WAKE_INFORMATION // (kernel-mode only)
    ProcessEnergyTrackingState,                     // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory,          // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,                 // q: ULONG
    ProcessTelemetryCoverage,                       // qs: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,                      // qs: Obsolete
    ProcessEnableReadWriteVmLogging,                // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation,                       // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection,                            // q: HANDLE
    ProcessDebugAuthInformation,                    // s: PROCESS_DEBUG_AUTH_INFORMATION // CiTool.exe -- device-id // PplDebugAuthorization // since RS4 // 90
    ProcessSystemResourceManagement,                // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber,                          // q: ULONGLONG
    ProcessLoaderDetour,                            // qs: Obsolete // since RS5
    ProcessSecurityDomainInformation,               // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation,       // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging,                           // q: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation,                   // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation,              // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation,          // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation,                // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets,            // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges,      // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange,                       // qs: Obsolete // since WIN11
    ProcessApplyStateChange,                        // qs: Obsolete
    ProcessEnableOptionalXStateFeatures,            // s: ULONG64 // EnableProcessOptionalXStateFeatures
    ProcessAltPrefetchParam,                        // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions,                     // s: HANDLE[]
    ProcessPriorityClassEx,                         // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation,                   // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority,                     // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority,                   // q: ULONG
    ProcessSchedulerSharedData,                     // s: PROCESS_SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
    ProcessSlistRollbackInformation,                // qs: no input buffer, length 0 on set, current process only
    ProcessNetworkIoCounters,                       // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue,               // q: PROCESS_TEB_VALUE_INFORMATION // NtCurrentProcess
    ProcessEnclaveAddressSpaceRestriction,          // qs: Obsolete // since 25H2
    ProcessAvailableCpus,                           // qs: Obsolete // PROCESS_AVAILABLE_CPUS_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

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

#define GDI_HANDLE_BUFFER_SIZE      34

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;

} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;               // Points to the loaded modules (main EXE usually)
    LIST_ENTRY InMemoryOrderModuleList;             // Points to all modules (EXE and all DLLs)
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;                             // Base address of the module
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG  Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    PVOID Unknown1;
    PVOID Unknown2;
    PVOID Unknown3;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;              //
    BOOLEAN SpareBool;                  //
    HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    HANDLE SystemReserved;
    PVOID  AtlThunkSListPtr32;
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    //
    // Passed up from MmCreatePeb from Session Manager registry key
    //

    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;

    //
    // Where heap manager keeps track of all heaps created for a process
    // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;

    //
    //
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;

    //
    // Following fields filled in by MmCreatePeb from system values and/or
    // image header. These fields have changed since Windows NT 4.0,
    // so use with caution
    //

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

} PEB, * PPEB;

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define PS_REQUEST_BREAKAWAY                    1
#define PS_NO_DEBUG_INHERIT                     2
#define PS_INHERIT_HANDLES                      4
#define PS_LARGE_PAGES                          8
#define PS_ALL_FLAGS                            (PS_REQUEST_BREAKAWAY | PS_NO_DEBUG_INHERIT  | PS_INHERIT_HANDLES   | PS_LARGE_PAGES)

#define RTL_USER_PROC_PARAMS_NORMALIZED			0x00000001
#define RTL_USER_PROC_PROFILE_USER				0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL			0x00000004
#define RTL_USER_PROC_PROFILE_SERVER			0x00000008
#define RTL_USER_PROC_RESERVE_1MB				0x00000020
#define RTL_USER_PROC_RESERVE_16MB				0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE			0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT		0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL		0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT		0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING			0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS				0x00020000

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI* pNtOpenFile)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
);

typedef NTSTATUS (NTAPI* pNtSetInformationFile)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (NTAPI* pNtWriteFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
);

typedef NTSTATUS (NTAPI* pNtCreateSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

typedef NTSTATUS (NTAPI* pNtCreateProcessEx)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
);

typedef NTSTATUS (NTAPI* pNtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* pNtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING                 ImagePathName,
    PUNICODE_STRING                 DllPath,
    PUNICODE_STRING                 CurrentDirectory,
    PUNICODE_STRING                 CommandLine,
    PVOID                           Environment,
    PUNICODE_STRING                 WindowTitle,                // set to NULL
    PUNICODE_STRING                 DesktopInfo,                // set to NULL
    PUNICODE_STRING                 ShellInfo,                  // set to NULL
    PUNICODE_STRING                 RuntimeData,                // set to NULL
    ULONG                           Flags
    );

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    HANDLE		ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR	ZeroBits,
    PSIZE_T		RegionSize,
    ULONG		AllocationType,
    ULONG		Protect
    );


typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
    HANDLE        ProcessHandle,
    PVOID         BaseAddress,
    PVOID         Buffer,
    SIZE_T        NumberOfBytesToWrite,
    PSIZE_T		  NumberOfBytesWritten
    );

typedef NTSTATUS (NTAPI* fnRtlDosPathNameToNtPathName_U_WithStatus)(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR* FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);

typedef NTSTATUS (NTAPI* fnNtReadVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

typedef struct
{

    struct
    {

        HMODULE Ntdll;

    } Module;

    struct
    {

        pNtCreateProcessEx                          NtCreateProcessEx;
        pNtCreateSection                            NtCreateSection;
        pNtCreateThreadEx                           NtCreateThreadEx;
        pNtQueryInformationProcess                  NtQueryInformationProcess;
        pNtWriteFile                                NtWriteFile;
        pNtSetInformationFile                       NtSetInformationFile;
        pNtOpenFile                                 NtOpenFile;
        fnRtlCreateProcessParametersEx              RtlCreateProcessParametersEx;
        fnNtAllocateVirtualMemory                   NtAllocateVirtualMemory;
        fnNtWriteVirtualMemory                      NtWriteVirtualMemory;
        fnRtlDosPathNameToNtPathName_U_WithStatus   RtlDosPathNameToNtPathName_U_WithStatus;
        fnNtReadVirtualMemory                       NtReadVirtualMemory;

    } Ntapi;

} Win32, *pWin32;

BOOL ReadTargetFileW
(
    _In_ LPCWSTR PeName,
    _Out_ SIZE_T* BufferSize,
    _Out_ LPVOID* lpBuffer
);

BOOLEAN CreateFileSection
(
    _In_ pWin32 Win32,
    _In_ LPCWSTR FilePath,
    _In_ PVOID PayloadBuffer,
    _In_ SIZE_T PayloadSize,
    _Out_ HANDLE* GhostSectionHandle
);

BOOLEAN CreateTempPath
(
    _In_ pWin32 Win32,
    _Out_ WCHAR* NewTmpPath
);

BOOLEAN CreateGhostedProcess
(
    _In_ LPCWSTR TargetFilePayload,
    _In_ HANDLE SectionHandle,
    _In_ PVOID PayloadBuffer,
    _In_ pWin32 Win32
);

