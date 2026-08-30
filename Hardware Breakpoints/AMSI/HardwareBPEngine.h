#include <Windows.h>
#include <stdio.h>
#include <amsi.h>

#pragma comment(lib, "amsi.lib")

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())
#define NT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

ULONG InitializeHardwareBPEngine(PEXCEPTION_POINTERS ExceptionInfo);

BOOLEAN SetHardwareBreakpoint
(
	_In_ PVOID FunctionAddress
);

BOOLEAN RemoveHardwareBreakpoint(void);

LPCSTR GetAmsiResultValue(AMSI_RESULT Result);