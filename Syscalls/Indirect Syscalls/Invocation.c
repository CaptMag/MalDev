#include "Syscalls.h"

BOOLEAN ExecuteIndirectSyscalls
(
	_In_ SIZE_T PayloadSize
)
{

	NTSTATUS	Status				= STATUS_SUCCESS;
	SyscallInfo SyscallConfig		= { 0 };
	HMODULE		NtdllBaseAddress	= NULL;
	PVOID		Payload				= NULL;

	NtdllBaseAddress = LoadDllModule(ntdll_dll_HASH);

	if (!InvokeSyscalls(&SyscallConfig, NtdllBaseAddress, NtAllocateVirtualMemory_HASH))
	{
		PRINT_ERROR("InvokeSyscalls");
		return FALSE;
	}

	INFO("[0x%p] [0x%p] [0x%d] Function Address | Syscall Address | SSN",
		SyscallConfig.SyscallInfo.FunctionAddress, SyscallConfig.SyscallInfo.SyscallInstruction, SyscallConfig.SyscallInfo.SyscallNumber);

	OKAY("Executing Via Indirect Syscalls!");

	InitializeSyscalls(SyscallConfig.SyscallInfo.SyscallNumber, SyscallConfig.SyscallInfo.SyscallInstruction);
	Status = ExecuteIndirect((HANDLE)-1, &Payload, 0, &PayloadSize, MEM_COMMIT, PAGE_READWRITE);
	if (Status != STATUS_SUCCESS)
	{
		NTERROR("NtAllocateVirtualMemory");
		return FALSE;
	}

	return TRUE;

}