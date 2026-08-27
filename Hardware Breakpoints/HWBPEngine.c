#include "HWBPEngine.h"

ULONG InitializeHardwareBPEngine(PEXCEPTION_POINTERS ExceptionInfo)
{

	ULONG_PTR	ReturnAddress		= 0;
	PVOID		ExceptionAddress	= ExceptionInfo->ExceptionRecord->ExceptionAddress;
	PCONTEXT	Ctx					= ExceptionInfo->ContextRecord;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{

		if (ExceptionAddress == Ctx->Dr0 ||
			ExceptionAddress == Ctx->Dr1 ||
			ExceptionAddress == Ctx->Dr2 ||
			ExceptionAddress == Ctx->Dr3)
		{

			INFO("[0x%p] Original RIP", (PVOID)Ctx->Rip);
			INFO("[0x%p] Original RSP", (PVOID)Ctx->Rsp);

			ReturnAddress	= *(ULONG_PTR*)Ctx->Rsp;
			Ctx->Rip		= ReturnAddress;
			Ctx->Rsp		+= 8;

			INFO("[0x%p] Modified RIP", (PVOID)Ctx->Rip);
			INFO("[0x%p] Modified RSP", (PVOID)Ctx->Rsp);

			Ctx->Rax = STATUS_SUCCESS; // This is on purpose, you will see that status code will be 0x0 regardless of invocation

			return EXCEPTION_CONTINUE_EXECUTION;

		}

	}

	return EXCEPTION_CONTINUE_EXECUTION;

}

BOOLEAN SetHardwareBreakpoint
(
	_In_ PVOID FunctionAddress
)
{

	CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(GetCurrentThread(), &Ctx))
	{
		PRINT_ERROR("GetThreadContext");
		return FALSE;
	}

	if (!Ctx.Dr0)
	{
		Ctx.Dr0 = (DWORD64)FunctionAddress;
		Ctx.Dr7 |= 0x01;
		INFO("Dr0 Filled!");
	}
	else if (!Ctx.Dr1)
	{
		Ctx.Dr1 = (DWORD64)FunctionAddress;
		Ctx.Dr7 |= 0x04;
		INFO("Dr1 Filled!");
	}
	else if (!Ctx.Dr2)
	{
		Ctx.Dr2 = (DWORD64)FunctionAddress;
		Ctx.Dr7 |= 0x10;
		INFO("Dr2 Filled!");
	}
	else if (!Ctx.Dr3)
	{
		Ctx.Dr3 = (DWORD64)FunctionAddress;
		Ctx.Dr7 |= 0x40;
		INFO("Dr3 Filled!");
	}
	else
	{
		INFO("All Registers Filled!");
		return FALSE;
	}

	if (!SetThreadContext(GetCurrentThread(), &Ctx))
	{
		PRINT_ERROR("SetThreadContext");
		return FALSE;
	}

	return TRUE;

}

BOOLEAN RemoveHardwareBreakpoint(void)
{

	CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(GetCurrentThread(), &Ctx))
	{
		PRINT_ERROR("GetThreadContext");
		return FALSE;
	}

	if (Ctx.Dr0)
	{
		Ctx.Dr0 = 0x00;
		Ctx.Dr7 &= ~0x01;
		INFO("Dr0 Cleared!");
	}
	if (Ctx.Dr1)
	{
		Ctx.Dr1 = 0x00;
		Ctx.Dr7 &= ~0x04;
		INFO("Dr1 Cleared!");
	}
	if (Ctx.Dr2)
	{
		Ctx.Dr2 = 0x00;
		Ctx.Dr7 &= ~0x10;
		INFO("Dr2 Cleared!");
	}
	if (Ctx.Dr3)
	{
		Ctx.Dr3 = 0x00;
		Ctx.Dr7 &= ~0x40;
		INFO("Dr3 Cleared!");
	}
	else 
	{ 
		INFO("No Breakpoints Set!"); 
		return FALSE; 
	}

	if (!SetThreadContext(GetCurrentThread(), &Ctx))
	{
		PRINT_ERROR("SetThreadContext");
		return FALSE;
	}

	return TRUE;

}