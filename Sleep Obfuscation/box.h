#pragma once
#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);
typedef NTSTATUS(WINAPI* NtSetEvent_t)(HANDLE EventHandle, PLONG PreviousState);
typedef NTSTATUS(NTAPI* pNtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef PVOID(NTAPI* pRtlCopyMemory)(PVOID Destination, const PVOID Source, SIZE_T Length);

typedef struct {
	VirtualProtect_t VirtualProtect;					/**>> Used To Change Memory Protection*/
	WaitForSingleObject_t WaitForSingleObject;			/**>> Used To Wait For a Handle To Finish Executing*/
	NtSetEvent_t NtSetEvent;							/**>> Used To Set an Event via NTAPI*/
	pNtContinue NtContinue;								/**>> Used To Continue Execution*/
	pNtWaitForSingleObject NtWaitForSingleObject;		/**>> Used To Wait For a Handle To Finish Executing via NTAPI*/
	pRtlCopyMemory RtlCopyMemory;						/**>> Wrapper for memcpy*/
} WinApi, *pWinApi;

/**
* @brief
*	Used To Encrypt Payload with AES-256-GCM While Local Process is Sleeping
* 
* @param SleepTime
*	User-Specified Sleep time
* 
* @return
*	Nothing
*/
VOID SleepObfusc
(
	IN PLARGE_INTEGER SleepTime
);