#include "box.h"
#include <inttypes.h>

// https://www.strchr.com/performance_measurements_with_rdtsc
// https://www.ccsl.carleton.ca/~jamuir/rdtscpm1.pdf

UINT64 Rdtsc()
{

	UINT time_high, time_low;
	UINT end_high, end_low;
	volatile int x = 0; // CPU doesn't interfere (optimize)

	__asm {

		XOR eax, eax // Set EAX --> 0
		cpuid // Serialization
		rdtsc // read timestamp to EAX

		mov time_low, eax
		mov time_high, edx
	}

	for (int i = 0; i < 100; i++) // random measuring code
	{
		x += i; // garbage for testing
	}

	__asm {

		XOR eax, eax
		cpuid	// Serialize
		rdtsc

		sub eax, time_low // find difference
		sbb edx, time_high

		mov end_low, eax // save result
		mov end_high, edx

	}

	UINT64 diff = ((UINT64)end_high << 32) | end_low;

	printf("CPU Cycles Completed: %" PRIu64 "\n", diff);

	return diff;

}

BOOL ChkDebug()
{

	UINT64 Cycles = Rdtsc();

	const UINT64 Range = 2000;

	if (Cycles > Range) // Takes longer than average RDTSC Instruction
	{
		printf("[!] Debugger Detected! Cycles %" PRIu64 "\n", Cycles);
		return TRUE; // most likely a debugger
	}

	printf("[+] Normal Execution. Cycles %" PRIu64 "\n", Cycles);
	return FALSE; // most likely NO debugger

}