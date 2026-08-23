#include <Windows.h>
#include <winreg.h>
#include <stdio.h>

#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG " Failed! Error: 0x%lx""\n", GetLastError())

BOOLEAN PersistViaWindowsServices();