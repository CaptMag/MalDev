#pragma once
#include <Windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)

typedef NTSTATUS(WINAPI* _SystemFunction033) (
	struct ustring* data,
	struct ustring* key);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} data, key;