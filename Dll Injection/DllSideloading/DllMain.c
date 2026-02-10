#include <Windows.h>
#pragma comment(lib, "user32.lib")

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p)
{
    if (r == DLL_PROCESS_ATTACH)
        MessageBoxA(0, "Pwned!", "xwizard", 0);
    return TRUE;
}