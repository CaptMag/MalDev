#include "box.h"

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        LOADAPIHASH(fnLoadLibraryA, pLoadLibraryA, KERNEL32HASH, LOADLIBRARYAHASH);

        HMODULE hUser32 = pLoadLibraryA("user32.dll");
        if (hUser32)
        {
            LOADAPIHASH(fnMessageBoxA, pMessageBoxA, USER32HASH, MESSAGEBOXAHASH);
            if (pMessageBoxA)
                pMessageBoxA(NULL, "Hello", "Hello", MB_OK);
        }
    }
    return TRUE;
}