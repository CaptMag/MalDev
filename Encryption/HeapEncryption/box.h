#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

typedef NTSTATUS(WINAPI* _SystemFunction033) (
	struct ustring* data,
	struct ustring* key);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} data, key;

BOOL HeapEncrypt();

BOOL HeapSleep
(
	DWORD SleepTime
);