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
#define NT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

typedef ULONGLONG REGHANDLE, * PREGHANDLE;

typedef struct _EVENT_DESCRIPTOR
{
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR, * PEVENT_DESCRIPTOR;

typedef struct _EVENT_DATA_DESCRIPTOR EVENT_DATA_DESCRIPTOR, * PEVENT_DATA_DESCRIPTOR;

typedef ULONG (NTAPI* fnEtwEventWrite)(
    _In_ REGHANDLE RegHandle,
    _In_ PEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
);

typedef ULONG (NTAPI* fnEtwEventWriteFull)(
    _In_ REGHANDLE RegHandle,
    _In_ PEVENT_DESCRIPTOR EventDescriptor,
    _In_ USHORT EventProperty,
    _In_opt_ LPCGUID ActivityId,
    _In_opt_ LPCGUID RelatedActivityId,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
);

typedef NTSTATUS (NTAPI* fnNtTraceEvent)(
    _In_opt_ HANDLE TraceHandle,
    _In_ ULONG Flags,
    _In_ ULONG FieldSize,
    _In_ PVOID Fields
);

typedef NTSTATUS(NTAPI* fnNtTraceControl)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

ULONG InitializeHardwareBPEngine(PEXCEPTION_POINTERS ExceptionInfo);

BOOLEAN SetHardwareBreakpoint
(
	_In_ PVOID FunctionAddress
);

BOOLEAN RemoveHardwareBreakpoint(void);