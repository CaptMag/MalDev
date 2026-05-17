#include "box.h"

VOID Payload()
{
	MessageBoxA(NULL, "Reflective Dll is Successful!", "Krakatowa!", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		Payload();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}