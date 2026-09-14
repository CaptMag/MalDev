#include <Windows.h>

VOID Payload(void)
{
	MessageBoxW(NULL, L"Dll Injector", L"Dll Injector", (MB_OK | MB_ICONEXCLAMATION));
}

BOOLEAN __stdcall DllMain
(
	_In_ HMODULE Module,
	_In_ DWORD Reason,
	_In_ PVOID Reserved
)
{

	switch (Reason)
	{
		case DLL_PROCESS_ATTACH:
			Payload();
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
	}

	return TRUE;

}