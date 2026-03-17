#include "common.h"
#include "BSOD.h"

BOOL BlueScreen()
{

	NTSTATUS status = NULL;
	BOOLEAN enabled = FALSE;
	ULONG response = 0;

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

	pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	pdef_NtRaiseHardError NtRaiseHardError = (pdef_NtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");

	status = RtlAdjustPrivilege(SHUTDOWN_PRIVILGE, TRUE, FALSE, &enabled);
	if (!status != STATUS_SUCCESS)
	{
		WARN("Failed To Adjust User Privileges!");
		PRINT_ERROR("RtlAdjustPrivilege");
		return FALSE;
	}

	status = NtRaiseHardError((NTSTATUS)(0xC0000000 | ((rand() % 10) << 8) | ((rand() % 16) << 4) | rand() % 16), 0, 0, 0, OPTION_SHUTDOWN, &response); // https://github.com/AgnivaMaity/NtRaiseHardError-Example/blob/main/NtRaiseHardError.c#L51
	if (status != STATUS_SUCCESS)
	{
		WARN("Failed To Raise Hard Error!");
		PRINT_ERROR("NtRaiseHardError");
		return FALSE;
	}

	return TRUE;

}
