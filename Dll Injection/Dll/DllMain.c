#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        MessageBoxA(NULL, "Testing", "Hello", MB_OK);
        break;
    }
    return TRUE;
}