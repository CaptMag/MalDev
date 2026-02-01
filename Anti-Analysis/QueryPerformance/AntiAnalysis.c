#include "box.h"

// https://stackoverflow.com/questions/49668/getlocaltime-api-time-resolution

BOOL QueryInformation()
{

	DWORD_PTR oldMask = SetThreadAffinityMask(GetCurrentThread(), 0x01);

	LARGE_INTEGER start, frequency, end;
	volatile int x = 0; // non-optomized

	if (!QueryPerformanceFrequency(&frequency))
	{
		PRINT_ERROR("QueryPerformanceFrequency");
		return FALSE;
	}

	if (!QueryPerformanceCounter(&start))
	{
		PRINT_ERROR("QueryPerformanceCounter");
		return FALSE;
	}

	// garbage func
	for (int i = 0; i < 1000000; i++) // has to be large due to fast calculation
	{
		x += i * i;
		x = x % 1000;
	}

	if (!QueryPerformanceCounter(&end))
	{
		PRINT_ERROR("QueryPerformanceCounter");
		return FALSE;
	}

	SetThreadAffinityMask(GetCurrentThread(), oldMask);

	LONGLONG Elapsed = (end.QuadPart - start.QuadPart);

	LONGLONG MicroElapsed = (Elapsed * 1000000) / frequency.QuadPart;

	INFO("Frequency: %lld Hz", frequency.QuadPart);
	INFO("Elapsed ticks: %lld", Elapsed);
	INFO("Elapsed Microseconds: %lld", MicroElapsed);

	const LONGLONG THRESHOLD = 5000;  // 5ms
	if (MicroElapsed > THRESHOLD)
	{
		INFO("Possible debugger detected!");
		return FALSE;
	}

	return TRUE;

}