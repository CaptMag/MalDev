
#pragma once
#ifndef BOX_H
#define BOX_H

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)


BOOL ShellInject
(
	IN PBYTE pShellcode,
	IN SIZE_T sShellSize
);


#endif