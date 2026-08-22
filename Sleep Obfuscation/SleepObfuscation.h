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
#define NT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%08X""\n", Status)

#define LOADAPI(Type, Name, Module) \
Type Name = (Type)GetProcAddress(GetModuleHandleW(Module), #Name);

#define CLOSEHANDLE(Handle) \
if (Handle != NULL && Handle != INVALID_HANDLE_VALUE) \
	printf("[0x%p] Handle Closed!", Handle); CloseHandle(Handle);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

// https://github.com/kyleavery/AceLdr/blob/main/src/include.h#L15

#define EasyRop4(Chain, Index, Api, Param1, Param2, Param3, Param4) \
	do { \
		Chain[Index].Rip = (DWORD64)(Api); \
		Chain[Index].Rcx = (DWORD64)(Param1); \
		Chain[Index].Rdx = (DWORD64)(Param2); \
		Chain[Index].R8  = (DWORD64)(Param3); \
		Chain[Index].R9  = (DWORD64)(Param4); \
	} while(0)


#define EasyRop3(Chain, Index, Api, Param1, Param2, Param3) \
	do { \
		Chain[Index].Rip = (DWORD64)(Api); \
		Chain[Index].Rcx = (DWORD64)(Param1); \
		Chain[Index].Rdx = (DWORD64)(Param2); \
		Chain[Index].R8  = (DWORD64)(Param3); \
	} while(0)


#define EasyRop2(Chain, Index, Api, Param1, Param2) \
	do { \
		Chain[Index].Rip = (DWORD64)(Api); \
		Chain[Index].Rcx = (DWORD64)(Param1); \
		Chain[Index].Rdx = (DWORD64)(Param2); \
	} while(0)


#define EasyRop1(Chain, Index, Api, Param1) \
	do { \
		Chain[Index].Rip = (DWORD64)(Api); \
		Chain[Index].Rcx = (DWORD64)(Param1); \
	} while(0)


#define EasyRop0(Chain, Index, Api) \
	do { \
		Chain[Index].Rip = (DWORD64)(Api); \
	} while(0)


VOID RC4SleepObfuscation
(
	_In_ DWORD SleepTime
);