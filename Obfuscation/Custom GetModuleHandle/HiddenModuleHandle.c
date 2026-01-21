#include "box.h"

// https://malwaretech.com/wiki/locating-modules-via-the-peb-x64
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record

PVOID GetModHandleWW
(
	IN wchar_t* target
)
{

	PPEB pPeb = (PPEB)__readgsqword(0x60); // 64-bit to get PEB
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	INFO("PEB Address: [0x%p]", pPeb);
	INFO("Ldr Address: [0x%p]", pLdr);

	PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY entry = head->Flink;

	/*

		InLoadOrderModuleList Structure (usually)

		Iterating through pLdr->InLoadOrderModuleList.Flink

		Application.exe
		ntdll.dll
		kernel32.dll
		kernelbase.dll

	*/

	for (PLIST_ENTRY pList = head->Flink; pList != head; pList = pList->Flink)
	{

		PLDR_DATA_TABLE_ENTRY ModuleDll =
			CONTAINING_RECORD(
				pList,
				LDR_DATA_TABLE_ENTRY,
				InLoadOrderLinks
			);

		if (_wcsicmp(ModuleDll->BaseDllName.Buffer, target) == 0)
		{
			OKAY("Found Address for %ls | Base Address: [0x%p]", target, ModuleDll->DllBase);
			return ModuleDll->DllBase;
		}
	}


	return;
}