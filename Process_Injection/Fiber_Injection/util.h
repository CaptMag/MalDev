#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())