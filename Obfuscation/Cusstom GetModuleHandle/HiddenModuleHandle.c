#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

BOOL IsEqual
(
	IN LPCWSTR Str1,
	IN LPCWSTR Str2
)

{

	// https://github.com/AbdouRoumi/Custom-GetModuleHandle/blob/master/Custom-GetModuleHandle/Custom-GetModuleHandle.cpp

	/*

		This function will allow a user-inputted DLL to be made without having it be case-sensitive

	*/


	WCHAR lStr1[MAX_PATH], lStr2[MAX_PATH];

	int Len1 = lstrlenW(Str1), Len2 = lstrlenW(Str2); // Used to get the string's length

	int i = 0;


	if (Len1 >= MAX_PATH || Len2 >= MAX_PATH)
	{
		return FALSE;
	}

	// make first string lowecase
	for (i = 0; i < Len1; i++)
	{
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i] = L'\0';

	// make second string lowecase
	for (i = 0; i < Len1; i++)
	{
		lStr2[i] = (WCHAR)tolower(Str2[i]);
	}
	lStr2[i] = L'\0';


	return (lstrcmpiW(lStr1, lStr2) == 0); // compared two strings to make sure they are equal
}


HMODULE HiddenModuleHandle
(
	IN LPCWSTR szModuleName
)

{

	PPEB pPeb = (PEB*)(__readgsqword(0x60));


	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);


	while (pDte)
	{

		if (pDte->FullDllName.Length != NULL)
		{

			if (IsEqual(pDte->FullDllName.Buffer, szModuleName))
			{
				wprintf(L"[+] DLL Found: %s\n", pDte->FullDllName.Buffer);
				return (HMODULE)(pDte->Reserved2[0]);
			}


		}
		else {
			break;
		}


		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}


int main()
{


	printf("[i] Original GetModuleHandleW Function: 0x%p\n", GetModuleHandleW(L"NTDLL.DLL"));

	printf("[i] Newer HiddenModuleHandle Function:  0x%p\n", HiddenModuleHandle(L"NTDLL.DLL"));

	return 0;

}