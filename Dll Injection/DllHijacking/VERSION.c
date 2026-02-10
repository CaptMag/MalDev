#include <Windows.h>
#pragma comment(lib, "user32.lib")

// MUST BE COMPILED IN X86 FOR GOOGLEUPDATE.EXE


/*
*
*               EXPORTED BY VERSION.dll
*               (Dumpbin Exported Func)
*
          1    0 000015C0 GetFileVersionInfoA
          2    1 00002430 GetFileVersionInfoByHandle
          3    2 000020A0 GetFileVersionInfoExA
          4    3 00001640 GetFileVersionInfoExW
          5    4 000015E0 GetFileVersionInfoSizeA
          6    5 000020C0 GetFileVersionInfoSizeExA
          7    6 00001660 GetFileVersionInfoSizeExW
          8    7 00001680 GetFileVersionInfoSizeW
          9    8 000016A0 GetFileVersionInfoW
         10    9 000020E0 VerFindFileA
         11    A 000025C0 VerFindFileW
         12    B 00002100 VerInstallFileA
         13    C 00003160 VerInstallFileW
         14    D          VerLanguageNameA (forwarded to KERNEL32.VerLanguageNameA)
         15    E          VerLanguageNameW (forwarded to KERNEL32.VerLanguageNameW) --> First to be used
         16    F 00001600 VerQueryValueA
         17   10 00001620 VerQueryValueW
*/

#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=_GetFileVersionInfoA@16")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=_GetFileVersionInfoByHandle@20")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=_GetFileVersionInfoExA@20")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=_GetFileVersionInfoExW@20")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=_GetFileVersionInfoSizeA@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=_GetFileVersionInfoSizeExA@12")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=_GetFileVersionInfoSizeExW@12")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=_GetFileVersionInfoSizeW@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=_GetFileVersionInfoW@16")
#pragma comment(linker, "/EXPORT:VerFindFileA=_VerFindFileA@32")
#pragma comment(linker, "/EXPORT:VerFindFileW=_VerFindFileW@32")
#pragma comment(linker, "/EXPORT:VerInstallFileA=_VerInstallFileA@32")
#pragma comment(linker, "/EXPORT:VerInstallFileW=_VerInstallFileW@32")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=KERNEL32.VerLanguageNameA")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=_VerLanguageNameW@12")
#pragma comment(linker, "/EXPORT:VerQueryValueA=_VerQueryValueA@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=_VerQueryValueW@16")


DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang)
{
    return 0;
}

// Stub slop
BOOL WINAPI GetFileVersionInfoA(LPCSTR f, DWORD h, DWORD l, LPVOID d) { return FALSE; }
BOOL WINAPI GetFileVersionInfoByHandle(HANDLE m, LPCWSTR f, DWORD h, DWORD l, LPVOID d) { return FALSE; }
BOOL WINAPI GetFileVersionInfoExA(DWORD fl, LPCSTR f, DWORD h, DWORD l, LPVOID d) { return FALSE; }
BOOL WINAPI GetFileVersionInfoExW(DWORD fl, LPCWSTR f, DWORD h, DWORD l, LPVOID d) { return FALSE; }
DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR f, LPDWORD h) { return 0; }
DWORD WINAPI GetFileVersionInfoSizeExA(DWORD fl, LPCSTR f, LPDWORD h) { return 0; }
DWORD WINAPI GetFileVersionInfoSizeExW(DWORD fl, LPCWSTR f, LPDWORD h) { return 0; }
DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h) { return 0; }
BOOL WINAPI GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD l, LPVOID d) { return FALSE; }
DWORD WINAPI VerFindFileA(DWORD u, LPCSTR f, LPCSTR w, LPCSTR a, LPSTR c, PUINT cl, LPSTR ds, PUINT dl) { return 0; }
DWORD WINAPI VerFindFileW(DWORD u, LPCWSTR f, LPCWSTR w, LPCWSTR a, LPWSTR c, PUINT cl, LPWSTR ds, PUINT dl) { return 0; }
DWORD WINAPI VerInstallFileA(DWORD u, LPCSTR sf, LPCSTR df, LPCSTR sd, LPCSTR dd, LPCSTR cd, LPSTR tf, PUINT tl) { return 0; }
DWORD WINAPI VerInstallFileW(DWORD u, LPCWSTR sf, LPCWSTR df, LPCWSTR sd, LPCWSTR dd, LPCWSTR cd, LPWSTR tf, PUINT tl) { return 0; }
BOOL WINAPI VerQueryValueA(LPCVOID b, LPCSTR s, LPVOID* buf, PUINT l) { return FALSE; }
BOOL WINAPI VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID* buf, PUINT l) { return FALSE; }

BOOL __stdcall DllMain(IN HINSTANCE hModule, IN DWORD Reason, IN LPVOID Reserved)
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Dll SideLoaded! :))))", "Playing with Google Update", MB_OK);
        break;
    }
    return TRUE;
}