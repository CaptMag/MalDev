#include "box.h"

int main()
{

	UCHAR message[] = "This is an example of Heap Encryption!";
	DWORD SleepTime = 10000;

	HANDLE hHeap = HeapCreate(0, 0, 0);
	if (hHeap == NULL)
	{
		WARN("Failed To Create a Heap!");
		PRINT_ERROR("HeapCreate");
		return FALSE;
	}

	LPVOID Memory = HeapAlloc(hHeap, 0, sizeof(message) * 2);
	if (Memory == NULL)
	{
		WARN("Failed To Allocate Memory onto The Heap!");
		PRINT_ERROR("HeapAlloc");
		HeapDestroy(hHeap);
		return FALSE;
	}

	INFO("Heap Address: %p", Memory);

	CopyMemory(Memory, message, sizeof(message));
	RtlSecureZeroMemory(message, sizeof(message));

	INFO("Press Enter To Encrypt!");
	getchar();

	if (!HeapSleep(SleepTime))
	{
		WARN("Failed To Encrypt/Decrypt Heap!");
		PRINT_ERROR("HeapSleep");
		return 1;
	}

	CHAR("Quit...");
	getchar();

	HeapFree(hHeap, 0, Memory);
	HeapDestroy(hHeap);

	return 0;

}